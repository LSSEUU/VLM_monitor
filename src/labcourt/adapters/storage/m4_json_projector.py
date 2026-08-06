"""Atomic, rebuildable JSON generations for one validated M4 snapshot."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.m4_projection import (
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationEntry,
    M4ProjectionGenerationManifest,
    m4_projection_relative_path,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    PathBoundaryViolation,
)

from .readonly_m4_artifacts import M4ArtifactAuthoritySnapshot, M4ValidatedDocument
from .secure_workspace import SecureWorkspace

MAX_M4_PROJECTION_BYTES = 64 * 1024 * 1024
_MAX_POINTER_BYTES = 8 * 1024
_MAX_INVENTORY_NAME_BYTES = 512
M4ProjectionFaultInjector = Callable[[str], None]


class M4ProjectionFailure(ContractViolation):
    """A validated SQLite snapshot could not be published atomically."""


@dataclass(frozen=True, slots=True)
class M4ProjectionResult:
    generation_id: str
    generation_directory: Path
    manifest_path: Path
    current_pointer_path: Path
    document_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class _ProjectionDocument:
    source: M4ValidatedDocument
    relative_path: str
    payload: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def entry(self) -> M4ProjectionGenerationEntry:
        return M4ProjectionGenerationEntry(
            kind=self.source.kind,
            artifact_id=self.source.artifact_id,
            relative_path=self.relative_path,
            sha256=self.sha256,
            size_bytes=len(self.payload),
        )


class M4JsonProjector:
    """Write an immutable generation, verify it, then replace ``current``."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M4ProjectionFaultInjector | None = None,
        max_projection_bytes: int = MAX_M4_PROJECTION_BYTES,
    ) -> None:
        if (
            not isinstance(max_projection_bytes, int)
            or isinstance(max_projection_bytes, bool)
            or max_projection_bytes <= 0
        ):
            raise ValueError("max_projection_bytes must be a positive integer")
        self._output_root = Path(output_root).absolute()
        self._fault_injector = fault_injector
        self._max_projection_bytes = max_projection_bytes
        try:
            self._output_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise M4ProjectionFailure("M4 projection workspace is unavailable") from None

    def publish(
        self,
        snapshot: M4ArtifactAuthoritySnapshot,
        target_directory: str | Path | None = None,
    ) -> M4ProjectionResult:
        run_id = require_portable_run_id(snapshot.run_id, "M4 projection run_id")
        expected_run_directory = self._output_root / run_id
        if (
            target_directory is not None
            and Path(target_directory).absolute() != expected_run_directory
        ):
            raise M4ProjectionFailure(
                "target_directory must be the canonical run directory below output_root"
            )
        if snapshot.failures:
            raise M4ProjectionFailure("M4 SQLite authority validation failed closed")
        documents = tuple(
            _ProjectionDocument(
                source=item,
                relative_path=m4_projection_relative_path(item.kind, item.artifact_id),
                payload=item.canonical_document.encode("utf-8"),
            )
            for item in snapshot.documents
        )
        entries = tuple(
            sorted((item.entry() for item in documents), key=lambda item: item.sort_key)
        )
        manifest = M4ProjectionGenerationManifest(
            run_id=run_id,
            authority_root_sha256=snapshot.authority_root_sha256,
            entries=entries,
        )
        manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        generation_relative = f"{run_id}/m4-projections/generations/{manifest.generation_id}"
        manifest_relative = f"{generation_relative}/manifest-{manifest_sha256}.json"
        pointer = M4ProjectionCurrentPointer(
            run_id=run_id,
            authority_root_sha256=snapshot.authority_root_sha256,
            generation_id=manifest.generation_id,
            manifest_relative_path=manifest_relative,
            manifest_sha256=manifest_sha256,
            manifest_size_bytes=len(manifest_bytes),
        )
        pointer_bytes = canonical_bytes(pointer.model_dump(mode="json"))
        if len(pointer_bytes) > _MAX_POINTER_BYTES:
            raise M4ProjectionFailure("M4 current pointer exceeds its fixed byte limit")
        total_bytes = sum(len(item.payload) for item in documents) + len(manifest_bytes)
        if total_bytes > self._max_projection_bytes:
            raise M4ProjectionFailure("M4 projection generation exceeds its byte budget")

        try:
            with SecureWorkspace(
                self._output_root,
                self._max_projection_bytes,
            ) as workspace:
                self._ensure_directories(
                    workspace,
                    run_id,
                    generation_relative,
                    documents,
                )
                for document in documents:
                    self._create_or_verify(
                        workspace,
                        f"{generation_relative}/{document.relative_path}",
                        document.payload,
                    )
                    self._fault(f"after_document:{document.source.kind.value}")
                self._create_or_verify(workspace, manifest_relative, manifest_bytes)
                self._fault("after_manifest")
                with workspace.projection_publish_lock(run_id):
                    self._verify_generation(
                        workspace,
                        generation_relative,
                        manifest_relative,
                        manifest,
                        manifest_bytes,
                        documents,
                    )
                    current_relative = f"{run_id}/m4-projections/current.json"
                    existing = self._read_current_if_present(workspace, current_relative)
                    if existing is not None:
                        existing_pointer, existing_bytes = existing
                        existing_manifest = self._read_manifest(workspace, existing_pointer)
                        self._verify_declared_generation(
                            workspace,
                            existing_pointer,
                            existing_manifest,
                        )
                        self._require_monotonic_successor(existing_manifest, manifest)
                        if existing_bytes == pointer_bytes:
                            return self._result(run_id, manifest, manifest_relative, documents)
                    self._fault("before_current")
                    self._atomic_write(workspace, current_relative, pointer_bytes)
                    self._fault("after_current")
                    installed = workspace.read_verified(
                        current_relative,
                        hashlib.sha256(pointer_bytes).hexdigest(),
                        max_bytes=len(pointer_bytes),
                    )
                    if installed.bytes != pointer_bytes:
                        raise M4ProjectionFailure("installed M4 current pointer changed")
                    self._verify_generation(
                        workspace,
                        generation_relative,
                        manifest_relative,
                        manifest,
                        manifest_bytes,
                        documents,
                    )
        except M4ProjectionFailure:
            raise
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            BudgetExceeded,
            PathBoundaryViolation,
        ) as exc:
            raise M4ProjectionFailure("secure workspace rejected M4 projection") from exc
        except Exception as exc:
            raise M4ProjectionFailure("M4 projection generation failed") from exc
        return self._result(run_id, manifest, manifest_relative, documents)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        run_id: str,
        generation_relative: str,
        documents: tuple[_ProjectionDocument, ...],
    ) -> None:
        directories = {
            run_id,
            f"{run_id}/projections",
            f"{run_id}/m4-projections",
            f"{run_id}/m4-projections/generations",
            generation_relative,
            f"{generation_relative}/documents",
            *(
                f"{generation_relative}/{item.relative_path.rsplit('/', maxsplit=1)[0]}"
                for item in documents
            ),
        }
        for directory in sorted(directories, key=lambda item: (item.count("/"), item)):
            workspace.ensure_private_directory(directory)

    def _verify_generation(
        self,
        workspace: SecureWorkspace,
        generation_relative: str,
        manifest_relative: str,
        manifest: M4ProjectionGenerationManifest,
        manifest_bytes: bytes,
        documents: tuple[_ProjectionDocument, ...],
    ) -> None:
        observed = workspace.read_verified(
            manifest_relative,
            hashlib.sha256(manifest_bytes).hexdigest(),
            max_bytes=len(manifest_bytes),
        )
        if observed.bytes != manifest_bytes:
            raise M4ProjectionFailure("M4 generation manifest changed")
        try:
            parsed = M4ProjectionGenerationManifest.model_validate_json(observed.bytes)
        except ValidationError:
            raise M4ProjectionFailure("M4 generation manifest contract is invalid") from None
        if parsed != manifest:
            raise M4ProjectionFailure("M4 generation manifest identity changed")
        expected = {item.relative_path: item for item in documents}
        for entry in manifest.entries:
            document = expected.get(entry.relative_path)
            if document is None or document.entry() != entry:
                raise M4ProjectionFailure("M4 manifest conflicts with projected documents")
            verified = workspace.read_verified(
                f"{generation_relative}/{entry.relative_path}",
                entry.sha256,
                max_bytes=entry.size_bytes,
            )
            if verified.bytes != document.payload or verified.size_bytes != entry.size_bytes:
                raise M4ProjectionFailure("M4 projected document changed")
        self._require_exact_inventory(
            workspace,
            generation_relative,
            {"documents", manifest_relative.rsplit("/", maxsplit=1)[-1]},
        )
        self._verify_document_inventory(workspace, generation_relative, manifest.entries)

    def _verify_declared_generation(
        self,
        workspace: SecureWorkspace,
        pointer: M4ProjectionCurrentPointer,
        manifest: M4ProjectionGenerationManifest,
    ) -> None:
        if (
            manifest.run_id != pointer.run_id
            or manifest.generation_id != pointer.generation_id
            or manifest.authority_root_sha256 != pointer.authority_root_sha256
        ):
            raise M4ProjectionFailure("current M4 pointer conflicts with its manifest")
        generation_relative = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[0]
        for entry in manifest.entries:
            workspace.read_verified(
                f"{generation_relative}/{entry.relative_path}",
                entry.sha256,
                max_bytes=entry.size_bytes,
            )
        self._require_exact_inventory(
            workspace,
            generation_relative,
            {"documents", pointer.manifest_relative_path.rsplit("/", maxsplit=1)[-1]},
        )
        self._verify_document_inventory(workspace, generation_relative, manifest.entries)

    @classmethod
    def _verify_document_inventory(
        cls,
        workspace: SecureWorkspace,
        generation_relative: str,
        entries: tuple[M4ProjectionGenerationEntry, ...],
    ) -> None:
        by_directory: dict[str, set[str]] = defaultdict(set)
        for entry in entries:
            directory, name = entry.relative_path.rsplit("/", maxsplit=1)
            by_directory[directory].add(name)
        expected_directories = {directory.split("/", maxsplit=1)[1] for directory in by_directory}
        cls._require_exact_inventory(
            workspace,
            f"{generation_relative}/documents",
            expected_directories,
        )
        for directory, names in by_directory.items():
            cls._require_exact_inventory(
                workspace,
                f"{generation_relative}/{directory}",
                names,
            )

    @staticmethod
    def _require_exact_inventory(
        workspace: SecureWorkspace,
        relative_directory: str,
        expected_names: set[str],
    ) -> None:
        hints = workspace.list_projection_directory(
            relative_directory,
            max_items=len(expected_names) + 1,
            max_name_bytes=_MAX_INVENTORY_NAME_BYTES,
        )
        observed = {item.name for item in hints if item.name is not None}
        if (
            any(item.name is None for item in hints)
            or observed != expected_names
            or len(hints) != len(expected_names)
        ):
            raise M4ProjectionFailure("M4 generation inventory is not exact")

    @staticmethod
    def _read_current_if_present(
        workspace: SecureWorkspace,
        relative_path: str,
    ) -> tuple[M4ProjectionCurrentPointer, bytes] | None:
        try:
            observed = workspace.read_verified(relative_path, max_bytes=_MAX_POINTER_BYTES)
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        try:
            pointer = M4ProjectionCurrentPointer.model_validate_json(observed.bytes)
        except ValidationError:
            raise M4ProjectionFailure("existing M4 current pointer is invalid") from None
        if canonical_bytes(pointer.model_dump(mode="json")) != observed.bytes:
            raise M4ProjectionFailure("existing M4 current pointer is not canonical")
        return pointer, observed.bytes

    @staticmethod
    def _read_manifest(
        workspace: SecureWorkspace,
        pointer: M4ProjectionCurrentPointer,
    ) -> M4ProjectionGenerationManifest:
        observed = workspace.read_verified(
            pointer.manifest_relative_path,
            pointer.manifest_sha256,
            max_bytes=pointer.manifest_size_bytes,
        )
        try:
            manifest = M4ProjectionGenerationManifest.model_validate_json(observed.bytes)
        except ValidationError:
            raise M4ProjectionFailure("current M4 manifest is invalid") from None
        if canonical_bytes(manifest.model_dump(mode="json")) != observed.bytes:
            raise M4ProjectionFailure("current M4 manifest is not canonical")
        return manifest

    @staticmethod
    def _require_monotonic_successor(
        previous: M4ProjectionGenerationManifest,
        candidate: M4ProjectionGenerationManifest,
    ) -> None:
        if previous.run_id != candidate.run_id:
            raise M4ProjectionFailure("M4 projection successor belongs to another run")
        previous_entries = {
            (item.kind, item.artifact_id): (item.sha256, item.size_bytes)
            for item in previous.entries
        }
        candidate_entries = {
            (item.kind, item.artifact_id): (item.sha256, item.size_bytes)
            for item in candidate.entries
        }
        if any(candidate_entries.get(key) != value for key, value in previous_entries.items()):
            raise M4ProjectionFailure("M4 projection candidate is stale or rewrites authority")
        if len(previous_entries) == len(candidate_entries) and (
            previous.authority_root_sha256 != candidate.authority_root_sha256
        ):
            raise M4ProjectionFailure("M4 projection root changed without an append")

    @staticmethod
    def _create_or_verify(
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
    ) -> None:
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        try:
            created = workspace.create_new(relative_path, payload, expected_sha256)
        except ArtifactConflict:
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    existing = workspace.read_verified(
                        relative_path,
                        expected_sha256,
                        max_bytes=len(payload),
                    )
                    break
                except PathBoundaryViolation as error:
                    if error.reason_code == "WINDOWS_OPEN_32" and time.monotonic() < deadline:
                        time.sleep(0.005)
                        continue
                    raise
            if existing.bytes != payload:
                raise M4ProjectionFailure("content-addressed M4 projection conflicts") from None
            return
        if created.bytes != payload:
            raise M4ProjectionFailure("created M4 projection differs from verified bytes")

    @staticmethod
    def _atomic_write(
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
    ) -> None:
        parent, name = relative_path.rsplit("/", maxsplit=1)
        temporary = f"{parent}/.{name}.{uuid4().hex}.tmp"
        sha256 = hashlib.sha256(payload).hexdigest()
        temporary_exists = False
        try:
            created = workspace.create_new(temporary, payload, sha256)
            temporary_exists = True
            if created.bytes != payload:
                raise M4ProjectionFailure("temporary M4 pointer changed")
            installed = workspace.replace_verified(temporary, relative_path, sha256)
            temporary_exists = False
            if installed.bytes != payload:
                raise M4ProjectionFailure("installed M4 pointer changed")
        finally:
            if temporary_exists:
                try:
                    workspace.delete_verified_temporary(temporary, sha256)
                except PathBoundaryViolation as error:
                    if error.reason_code != "FILE_MISSING":
                        raise

    def _result(
        self,
        run_id: str,
        manifest: M4ProjectionGenerationManifest,
        manifest_relative: str,
        documents: tuple[_ProjectionDocument, ...],
    ) -> M4ProjectionResult:
        generation = (
            self._output_root / run_id / "m4-projections" / "generations" / manifest.generation_id
        )
        return M4ProjectionResult(
            generation_id=manifest.generation_id,
            generation_directory=generation,
            manifest_path=self._output_root / Path(manifest_relative),
            current_pointer_path=self._output_root / run_id / "m4-projections" / "current.json",
            document_paths=tuple(generation / item.relative_path for item in documents),
        )

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)


__all__ = [
    "MAX_M4_PROJECTION_BYTES",
    "M4JsonProjector",
    "M4ProjectionFailure",
    "M4ProjectionResult",
]
