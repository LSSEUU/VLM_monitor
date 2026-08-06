"""Atomic named JSONL generations derived from validated M5 SQLite state."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.m5_projection import (
    M5ProjectionCurrentPointer,
    M5ProjectionFileKind,
    M5ProjectionGenerationEntry,
    M5ProjectionGenerationManifest,
    M5ProjectionRecordReceipt,
    m5_projection_authority_kinds,
    m5_projection_relative_path,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    PathBoundaryViolation,
)

from .readonly_m5_artifacts import M5ArtifactAuthoritySnapshot, M5ValidatedDocument
from .secure_workspace import SecureWorkspace

MAX_M5_PROJECTION_BYTES = 64 * 1024 * 1024
_MAX_POINTER_BYTES = 8 * 1024
_MAX_NAME_BYTES = 512
M5ProjectionFaultInjector = Callable[[str], None]


class M5ProjectionFailure(ContractViolation):
    """A validated M5 snapshot could not be published atomically."""


@dataclass(frozen=True, slots=True)
class M5ProjectionResult:
    generation_id: str
    generation_directory: Path
    manifest_path: Path
    current_pointer_path: Path
    jsonl_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class _JsonlFile:
    file_kind: M5ProjectionFileKind
    documents: tuple[M5ValidatedDocument, ...]
    payload: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def entry(self) -> M5ProjectionGenerationEntry:
        return M5ProjectionGenerationEntry(
            file_kind=self.file_kind,
            relative_path=m5_projection_relative_path(self.file_kind),
            sha256=self.sha256,
            size_bytes=len(self.payload),
            record_count=len(self.documents),
            authority_kinds=m5_projection_authority_kinds(self.file_kind),
            records=tuple(
                M5ProjectionRecordReceipt(
                    authority_kind=item.kind,
                    artifact_id=item.artifact_id,
                    sha256=item.document_sha256,
                )
                for item in self.documents
            ),
        )


class M5JsonlProjector:
    """Write, re-read, and select exactly one complete M5 generation."""

    def __init__(
        self,
        output_root: str | Path,
        *,
        fault_injector: M5ProjectionFaultInjector | None = None,
        max_projection_bytes: int = MAX_M5_PROJECTION_BYTES,
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
            raise M5ProjectionFailure("M5 projection workspace is unavailable") from None

    def publish(self, snapshot: M5ArtifactAuthoritySnapshot) -> M5ProjectionResult:
        run_id = require_portable_run_id(snapshot.run_id, "M5 projection run_id")
        if snapshot.failures:
            raise M5ProjectionFailure("M5 SQLite authority validation failed closed")
        files = _jsonl_files(snapshot.documents)
        entries = tuple(item.entry() for item in files)
        manifest = M5ProjectionGenerationManifest(
            run_id=run_id,
            authority_root_sha256=snapshot.authority_root_sha256,
            authority_record_count=len(snapshot.documents),
            case_root_count=len(snapshot.case_roots),
            entries=entries,
        )
        manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        generation_relative = f"{run_id}/m5-projections/generations/{manifest.generation_id}"
        manifest_relative = f"{generation_relative}/manifest-{manifest_sha256}.json"
        pointer = M5ProjectionCurrentPointer(
            run_id=run_id,
            authority_root_sha256=snapshot.authority_root_sha256,
            generation_id=manifest.generation_id,
            manifest_relative_path=manifest_relative,
            manifest_sha256=manifest_sha256,
            manifest_size_bytes=len(manifest_bytes),
        )
        pointer_bytes = canonical_bytes(pointer.model_dump(mode="json"))
        total = sum(len(item.payload) for item in files) + len(manifest_bytes)
        if len(pointer_bytes) > _MAX_POINTER_BYTES or total > self._max_projection_bytes:
            raise M5ProjectionFailure("M5 projection exceeds its byte budget")
        try:
            with SecureWorkspace(self._output_root, self._max_projection_bytes) as workspace:
                self._ensure_directories(workspace, run_id, generation_relative)
                for item in files:
                    self._create_or_verify(
                        workspace,
                        f"{generation_relative}/{m5_projection_relative_path(item.file_kind)}",
                        item.payload,
                    )
                    self._fault(f"after_file:{item.file_kind.value}")
                self._create_or_verify(workspace, manifest_relative, manifest_bytes)
                self._fault("after_manifest")
                with workspace.projection_publish_lock(run_id):
                    self._verify_generation(
                        workspace,
                        generation_relative,
                        manifest_relative,
                        manifest,
                        manifest_bytes,
                        files,
                    )
                    current_relative = f"{run_id}/m5-projections/current.json"
                    existing = self._read_current_if_present(workspace, current_relative)
                    if existing is not None:
                        existing_pointer, existing_bytes = existing
                        previous = self._read_manifest(workspace, existing_pointer)
                        self._verify_declared_generation(workspace, existing_pointer, previous)
                        self._require_monotonic_successor(previous, manifest)
                        if existing_bytes == pointer_bytes:
                            return self._result(run_id, manifest, manifest_relative)
                    self._fault("before_current")
                    self._atomic_write(workspace, current_relative, pointer_bytes)
                    self._fault("after_current")
                    installed = workspace.read_verified(
                        current_relative,
                        hashlib.sha256(pointer_bytes).hexdigest(),
                        max_bytes=len(pointer_bytes),
                    )
                    if installed.bytes != pointer_bytes:
                        raise M5ProjectionFailure("installed M5 current pointer changed")
                    self._verify_generation(
                        workspace,
                        generation_relative,
                        manifest_relative,
                        manifest,
                        manifest_bytes,
                        files,
                    )
        except M5ProjectionFailure:
            raise
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            BudgetExceeded,
            PathBoundaryViolation,
        ) as exc:
            raise M5ProjectionFailure("secure workspace rejected M5 projection") from exc
        except Exception as exc:
            raise M5ProjectionFailure("M5 projection generation failed") from exc
        return self._result(run_id, manifest, manifest_relative)

    @staticmethod
    def _ensure_directories(
        workspace: SecureWorkspace,
        run_id: str,
        generation_relative: str,
    ) -> None:
        for directory in (
            run_id,
            f"{run_id}/projections",
            f"{run_id}/m5-projections",
            f"{run_id}/m5-projections/generations",
            generation_relative,
        ):
            workspace.ensure_private_directory(directory)

    def _verify_generation(
        self,
        workspace: SecureWorkspace,
        generation_relative: str,
        manifest_relative: str,
        manifest: M5ProjectionGenerationManifest,
        manifest_bytes: bytes,
        files: tuple[_JsonlFile, ...],
    ) -> None:
        observed = workspace.read_verified(
            manifest_relative,
            hashlib.sha256(manifest_bytes).hexdigest(),
            max_bytes=len(manifest_bytes),
        )
        if observed.bytes != manifest_bytes:
            raise M5ProjectionFailure("M5 generation manifest changed")
        parsed = self._parse_manifest(observed.bytes)
        if parsed != manifest:
            raise M5ProjectionFailure("M5 generation manifest identity changed")
        expected = {item.file_kind: item for item in files}
        for entry in manifest.entries:
            item = expected.get(entry.file_kind)
            if item is None or item.entry() != entry:
                raise M5ProjectionFailure("M5 manifest conflicts with JSONL content")
            verified = workspace.read_verified(
                f"{generation_relative}/{entry.relative_path}",
                entry.sha256,
                max_bytes=entry.size_bytes,
            )
            if verified.bytes != item.payload:
                raise M5ProjectionFailure("M5 JSONL content changed")
        self._require_exact_inventory(
            workspace,
            generation_relative,
            {
                *(entry.relative_path for entry in manifest.entries),
                manifest_relative.rsplit("/", maxsplit=1)[-1],
            },
        )

    def _verify_declared_generation(
        self,
        workspace: SecureWorkspace,
        pointer: M5ProjectionCurrentPointer,
        manifest: M5ProjectionGenerationManifest,
    ) -> None:
        if (
            manifest.run_id != pointer.run_id
            or manifest.generation_id != pointer.generation_id
            or manifest.authority_root_sha256 != pointer.authority_root_sha256
        ):
            raise M5ProjectionFailure("current M5 pointer conflicts with its manifest")
        generation = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[0]
        for entry in manifest.entries:
            workspace.read_verified(
                f"{generation}/{entry.relative_path}",
                entry.sha256,
                max_bytes=entry.size_bytes,
            )
        self._require_exact_inventory(
            workspace,
            generation,
            {
                *(entry.relative_path for entry in manifest.entries),
                pointer.manifest_relative_path.rsplit("/", maxsplit=1)[-1],
            },
        )

    @staticmethod
    def _require_monotonic_successor(
        previous: M5ProjectionGenerationManifest,
        candidate: M5ProjectionGenerationManifest,
    ) -> None:
        previous_records = {
            (item.authority_kind, item.artifact_id): item.sha256
            for entry in previous.entries
            for item in entry.records
        }
        candidate_records = {
            (item.authority_kind, item.artifact_id): item.sha256
            for entry in candidate.entries
            for item in entry.records
        }
        if previous.run_id != candidate.run_id or any(
            candidate_records.get(key) != value for key, value in previous_records.items()
        ):
            raise M5ProjectionFailure("M5 projection candidate is stale or rewrites authority")
        if len(previous_records) == len(candidate_records) and (
            previous.authority_root_sha256 != candidate.authority_root_sha256
        ):
            raise M5ProjectionFailure("M5 projection root changed without an append")

    @staticmethod
    def _read_current_if_present(
        workspace: SecureWorkspace,
        relative_path: str,
    ) -> tuple[M5ProjectionCurrentPointer, bytes] | None:
        try:
            observed = workspace.read_verified(relative_path, max_bytes=_MAX_POINTER_BYTES)
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        try:
            pointer = M5ProjectionCurrentPointer.model_validate_json(observed.bytes)
        except ValidationError:
            raise M5ProjectionFailure("existing M5 current pointer is invalid") from None
        if canonical_bytes(pointer.model_dump(mode="json")) != observed.bytes:
            raise M5ProjectionFailure("existing M5 current pointer is not canonical")
        return pointer, observed.bytes

    def _read_manifest(
        self,
        workspace: SecureWorkspace,
        pointer: M5ProjectionCurrentPointer,
    ) -> M5ProjectionGenerationManifest:
        observed = workspace.read_verified(
            pointer.manifest_relative_path,
            pointer.manifest_sha256,
            max_bytes=pointer.manifest_size_bytes,
        )
        return self._parse_manifest(observed.bytes)

    @staticmethod
    def _parse_manifest(payload: bytes) -> M5ProjectionGenerationManifest:
        try:
            manifest = M5ProjectionGenerationManifest.model_validate_json(payload)
        except ValidationError:
            raise M5ProjectionFailure("M5 projection manifest is invalid") from None
        if canonical_bytes(manifest.model_dump(mode="json")) != payload:
            raise M5ProjectionFailure("M5 projection manifest is not canonical")
        return manifest

    @staticmethod
    def _require_exact_inventory(
        workspace: SecureWorkspace,
        relative_directory: str,
        expected_names: set[str],
    ) -> None:
        hints = workspace.list_projection_directory(
            relative_directory,
            max_items=len(expected_names) + 1,
            max_name_bytes=_MAX_NAME_BYTES,
        )
        observed = {item.name for item in hints if item.name is not None}
        if (
            any(item.name is None for item in hints)
            or observed != expected_names
            or len(hints) != len(expected_names)
        ):
            raise M5ProjectionFailure("M5 generation inventory is not exact")

    @staticmethod
    def _create_or_verify(
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
    ) -> None:
        sha256 = hashlib.sha256(payload).hexdigest()
        try:
            created = workspace.create_new(relative_path, payload, sha256)
        except ArtifactConflict:
            existing = workspace.read_verified(relative_path, sha256, max_bytes=len(payload))
            if existing.bytes != payload:
                raise M5ProjectionFailure("content-addressed M5 projection conflicts") from None
            return
        if created.bytes != payload:
            raise M5ProjectionFailure("created M5 projection differs from verified bytes")

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
            workspace.create_new(temporary, payload, sha256)
            temporary_exists = True
            installed = workspace.replace_verified(temporary, relative_path, sha256)
            temporary_exists = False
            if installed.bytes != payload:
                raise M5ProjectionFailure("installed M5 current pointer changed")
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
        manifest: M5ProjectionGenerationManifest,
        manifest_relative: str,
    ) -> M5ProjectionResult:
        generation = (
            self._output_root / run_id / "m5-projections" / "generations" / manifest.generation_id
        )
        return M5ProjectionResult(
            generation_id=manifest.generation_id,
            generation_directory=generation,
            manifest_path=self._output_root / Path(manifest_relative),
            current_pointer_path=self._output_root / run_id / "m5-projections" / "current.json",
            jsonl_paths=tuple(generation / entry.relative_path for entry in manifest.entries),
        )

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)


def _jsonl_files(documents: tuple[M5ValidatedDocument, ...]) -> tuple[_JsonlFile, ...]:
    result: list[_JsonlFile] = []
    for file_kind in sorted(M5ProjectionFileKind, key=m5_projection_relative_path):
        kinds = m5_projection_authority_kinds(file_kind)
        selected = tuple(item for item in documents if item.kind in kinds)
        lines = (
            canonical_bytes(
                {
                    "authority_kind": item.kind.value,
                    "artifact_id": item.artifact_id,
                    "document_sha256": item.document_sha256,
                    "document": json.loads(item.canonical_document),
                }
            )
            for item in selected
        )
        result.append(_JsonlFile(file_kind, selected, b"".join(line + b"\n" for line in lines)))
    return tuple(result)


__all__ = [
    "MAX_M5_PROJECTION_BYTES",
    "M5JsonlProjector",
    "M5ProjectionFailure",
    "M5ProjectionFaultInjector",
    "M5ProjectionResult",
]
