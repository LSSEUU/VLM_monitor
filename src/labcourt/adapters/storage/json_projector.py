"""Whole-generation canonical projections from repository authority."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TypeVar
from uuid import UUID, uuid4

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.audit import AuditEntry, validate_audit_chain
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.projection_generation import (
    ProjectionArtifactKind,
    ProjectionCurrentPointer,
    ProjectionGenerationEntry,
    ProjectionGenerationManifest,
)
from labcourt.contracts.references import require_portable_run_id
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    PathBoundaryViolation,
)
from labcourt.ports.evidence_repository import AuditHead, EvidenceRepository

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_ATTEMPTS = 4
_MAX_INVENTORY_NAME_BYTES = 512
_MAX_CURRENT_POINTER_BYTES = 4 * 1024
MAX_PROJECTION_BYTES = 64 * 1024 * 1024
ProjectionFaultInjector = Callable[[str], None]
_ReadResult = TypeVar("_ReadResult")


class ProjectionFailure(ContractViolation):
    """A post-commit projection generation could not be published."""


@dataclass(frozen=True, slots=True)
class ProjectionResult:
    """Paths in the one complete generation selected by ``current.json``."""

    run_directory: Path
    generation_id: str
    current_pointer_path: Path
    manifest_path: Path
    events_path: Path
    audit_path: Path
    case_paths: tuple[Path, ...]
    pack_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class _ProjectionDocument:
    kind: ProjectionArtifactKind
    projection_id: str
    relative_path: str
    payload: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def entry(self) -> ProjectionGenerationEntry:
        return ProjectionGenerationEntry(
            kind=self.kind,
            projection_id=self.projection_id,
            relative_path=self.relative_path,
            sha256=self.sha256,
            size_bytes=len(self.payload),
        )


class JsonProjector:
    """Publish immutable generations, then atomically select one complete release."""

    def __init__(
        self,
        repository: EvidenceRepository,
        output_root: str | Path,
        fault_injector: ProjectionFaultInjector | None = None,
        max_projection_bytes: int = MAX_PROJECTION_BYTES,
    ) -> None:
        if (
            not isinstance(max_projection_bytes, int)
            or isinstance(max_projection_bytes, bool)
            or max_projection_bytes <= 0
        ):
            raise ValueError("max_projection_bytes must be a positive integer")
        root = Path(output_root).absolute()
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise ProjectionFailure("projection workspace root is unavailable") from None
        self._repository = repository
        self._output_root = root
        self._fault_injector = fault_injector
        self._max_projection_bytes = max_projection_bytes

    def project_run(
        self,
        run_id: str,
        target_directory: str | Path | None = None,
    ) -> ProjectionResult:
        require_portable_run_id(run_id, "projection run_id")
        self._run_directory(run_id, target_directory)
        head, documents = self._snapshot(run_id)
        entries = tuple(
            sorted((item.entry() for item in documents), key=lambda item: item.sort_key)
        )
        manifest = ProjectionGenerationManifest(
            run_id=run_id,
            audit_head_sequence=head.sequence,
            audit_head_hash=head.entry_hash,
            entries=entries,
        )
        manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        generation_relative = f"{run_id}/projections/generations/{manifest.generation_id}"
        manifest_relative = f"{generation_relative}/manifest-{manifest_sha256}.json"
        pointer = ProjectionCurrentPointer(
            run_id=run_id,
            audit_head_sequence=head.sequence,
            audit_head_hash=head.entry_hash,
            generation_id=manifest.generation_id,
            manifest_relative_path=manifest_relative,
            manifest_sha256=manifest_sha256,
            manifest_size_bytes=len(manifest_bytes),
        )
        pointer_bytes = canonical_bytes(pointer.model_dump(mode="json"))
        if len(pointer_bytes) > _MAX_CURRENT_POINTER_BYTES:
            raise ProjectionFailure("current projection pointer exceeds its fixed byte limit")

        try:
            with SecureWorkspace(self._output_root, self._max_projection_bytes) as workspace:
                for directory in (
                    run_id,
                    f"{run_id}/projections",
                    f"{run_id}/projections/generations",
                    generation_relative,
                    f"{generation_relative}/cases",
                    f"{generation_relative}/packs",
                ):
                    workspace.ensure_private_directory(directory)
                self._materialize_generation(
                    workspace,
                    generation_relative,
                    manifest_relative,
                    manifest_bytes,
                    documents,
                )
                self._fault("before_publish_lock")
                with workspace.projection_publish_lock(run_id):
                    committed = self._publish_locked(
                        workspace,
                        run_id,
                        generation_relative,
                        manifest_relative,
                        manifest,
                        manifest_bytes,
                        documents,
                        pointer,
                        pointer_bytes,
                    )
                    if committed is not None:
                        return committed
        except ProjectionFailure:
            raise
        except (
            ArtifactConflict,
            ArtifactIntegrityViolation,
            BudgetExceeded,
            PathBoundaryViolation,
        ) as exc:
            raise ProjectionFailure("secure projection workspace rejected an operation") from exc
        except Exception as exc:
            raise ProjectionFailure("projection generation failed") from exc

        return self._result(run_id, manifest, manifest_relative, documents)

    def _materialize_generation(
        self,
        workspace: SecureWorkspace,
        generation_relative: str,
        manifest_relative: str,
        manifest_bytes: bytes,
        documents: tuple[_ProjectionDocument, ...],
    ) -> None:
        for document in documents:
            self._create_or_verify(
                workspace,
                f"{generation_relative}/{document.relative_path}",
                document.payload,
            )
            self._fault(_document_fault_phase(document))
        self._fault("before_manifest_publish")
        self._create_or_verify(workspace, manifest_relative, manifest_bytes)
        self._fault("after_manifest_publish")

    def _publish_locked(
        self,
        workspace: SecureWorkspace,
        run_id: str,
        generation_relative: str,
        manifest_relative: str,
        manifest: ProjectionGenerationManifest,
        manifest_bytes: bytes,
        documents: tuple[_ProjectionDocument, ...],
        pointer: ProjectionCurrentPointer,
        pointer_bytes: bytes,
    ) -> ProjectionResult | None:
        self._verify_generation(
            workspace,
            generation_relative,
            manifest_relative,
            manifest,
            manifest_bytes,
            documents,
        )

        current_relative = f"{run_id}/projections/current.json"
        # This re-read occurs under the crash-released writer lock. It is the
        # monotonic compare-and-swap check, not a stale preflight.
        existing = self._read_current_if_present(workspace, current_relative)
        if existing is not None:
            existing_pointer, existing_bytes = existing
            if existing_pointer.run_id != run_id:
                raise ProjectionFailure("current projection belongs to another run")
            if existing_bytes == pointer_bytes:
                return self._result(run_id, manifest, manifest_relative, documents)
            if existing_pointer.audit_head_sequence > pointer.audit_head_sequence:
                raise ProjectionFailure("current projection is newer than the candidate")
            if (
                existing_pointer.audit_head_sequence == pointer.audit_head_sequence
                and existing_pointer.audit_head_hash != pointer.audit_head_hash
            ):
                raise ProjectionFailure("current projection conflicts at the same audit head")
        self._fault("before_current_publish")
        try:
            self._atomic_write(
                workspace,
                current_relative,
                pointer_bytes,
                jsonl=False,
            )
            self._fault("after_current_publish")
        except Exception as publication_error:
            # ``replace_verified`` may linearize the atomic rename and then lose
            # its verification receipt.  Re-open the commit point before deciding
            # whether this is a failed publication or an already committed one.
            try:
                committed = workspace.read_verified(
                    current_relative,
                    hashlib.sha256(pointer_bytes).hexdigest(),
                    max_bytes=len(pointer_bytes),
                )
            except Exception as verification_error:
                raise publication_error from verification_error
            if committed.bytes != pointer_bytes:
                raise publication_error from None
        self._verify_generation(
            workspace,
            generation_relative,
            manifest_relative,
            manifest,
            manifest_bytes,
            documents,
        )
        return None

    def project_case(
        self,
        run_id: str,
        case_id: str,
        target_directory: str | Path | None = None,
    ) -> Path:
        _require_case_id(case_id)
        result = self.project_run(run_id, target_directory)
        for path in result.case_paths:
            if path.name == f"{case_id}.json":
                return path
        raise ProjectionFailure("case is not present in the complete projection generation")

    def project_pack(
        self,
        run_id: str,
        pack_id: str,
        target_directory: str | Path | None = None,
    ) -> Path:
        _require_pack_id(pack_id)
        result = self.project_run(run_id, target_directory)
        for path in result.pack_paths:
            if path.name == f"{pack_id}.json":
                return path
        raise ProjectionFailure("pack is not present in the complete projection generation")

    def _snapshot(self, run_id: str) -> tuple[AuditHead, tuple[_ProjectionDocument, ...]]:
        for _ in range(_SNAPSHOT_ATTEMPTS):
            before = self._read(lambda: self._repository.get_audit_head(run_id))
            events = self._read(lambda: self._repository.list_events(run_id))
            audit_entries = self._read(lambda: self._repository.list_audit_entries(run_id))
            cases = tuple(
                self._read(
                    partial(
                        self._repository.load_case,
                        run_id,
                        event_case_id(event.event_id),
                    )
                ).case
                for event in events
            )
            pack_by_id = {
                indexed_pack.pack_id: self._read(
                    partial(self._repository.load_pack, run_id, indexed_pack.pack_id)
                )
                for case in cases
                for indexed_pack in case.evidence_packs
            }
            after = self._read(lambda: self._repository.get_audit_head(run_id))
            if before == after:
                self._verify_audit(run_id, audit_entries, before)
                break
        else:
            raise ProjectionFailure("authoritative run changed during projection snapshot")

        documents = [
            _ProjectionDocument(
                ProjectionArtifactKind.EVENTS_JSONL,
                run_id,
                "events.jsonl",
                _jsonl_bytes(tuple(event.model_dump(mode="json") for event in events)),
            ),
            _ProjectionDocument(
                ProjectionArtifactKind.AUDIT_JSONL,
                run_id,
                "audit.jsonl",
                _jsonl_bytes(tuple(entry.model_dump(mode="json") for entry in audit_entries)),
            ),
        ]
        documents.extend(
            _ProjectionDocument(
                ProjectionArtifactKind.CASE_JSON,
                case.case_id,
                f"cases/{case.case_id}.json",
                canonical_bytes(case.model_dump(mode="json")),
            )
            for case in cases
        )
        documents.extend(
            _ProjectionDocument(
                ProjectionArtifactKind.PACK_JSON,
                pack_id,
                f"packs/{pack_id}.json",
                canonical_bytes(pack_by_id[pack_id].model_dump(mode="json")),
            )
            for pack_id in sorted(pack_by_id)
        )
        return before, tuple(documents)

    def _verify_generation(
        self,
        workspace: SecureWorkspace,
        generation_relative: str,
        manifest_relative: str,
        manifest: ProjectionGenerationManifest,
        manifest_bytes: bytes,
        documents: tuple[_ProjectionDocument, ...],
    ) -> None:
        observed_manifest = workspace.read_verified(
            manifest_relative,
            hashlib.sha256(manifest_bytes).hexdigest(),
            max_bytes=len(manifest_bytes),
        )
        if observed_manifest.bytes != manifest_bytes:
            raise ProjectionFailure("projection manifest bytes changed")
        try:
            parsed = ProjectionGenerationManifest.model_validate_json(observed_manifest.bytes)
        except ValidationError:
            raise ProjectionFailure("projection manifest contract is invalid") from None
        if parsed != manifest:
            raise ProjectionFailure("projection manifest identity changed")
        by_path = {document.relative_path: document for document in documents}
        if tuple(entry.relative_path for entry in manifest.entries) != tuple(
            entry.relative_path
            for entry in sorted(manifest.entries, key=lambda item: item.sort_key)
        ):
            raise ProjectionFailure("projection manifest inventory order changed")
        for entry in manifest.entries:
            document = by_path.get(entry.relative_path)
            if document is None or document.entry() != entry:
                raise ProjectionFailure("projection manifest inventory conflicts with documents")
            observed = workspace.read_verified(
                f"{generation_relative}/{entry.relative_path}",
                entry.sha256,
                max_bytes=entry.size_bytes,
            )
            if observed.bytes != document.payload or observed.size_bytes != entry.size_bytes:
                raise ProjectionFailure("projection generation document changed")
        expected_root = {
            "events.jsonl",
            "audit.jsonl",
            "cases",
            "packs",
            manifest_relative.rsplit("/", maxsplit=1)[-1],
        }
        expected_cases = {
            entry.relative_path.split("/", maxsplit=1)[1]
            for entry in manifest.entries
            if entry.kind == ProjectionArtifactKind.CASE_JSON
        }
        expected_packs = {
            entry.relative_path.split("/", maxsplit=1)[1]
            for entry in manifest.entries
            if entry.kind == ProjectionArtifactKind.PACK_JSON
        }
        self._require_exact_inventory(workspace, generation_relative, expected_root)
        self._require_exact_inventory(
            workspace,
            f"{generation_relative}/cases",
            expected_cases,
        )
        self._require_exact_inventory(
            workspace,
            f"{generation_relative}/packs",
            expected_packs,
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
        if any(hint.name is None for hint in hints):
            raise ProjectionFailure("projection generation inventory is unsafe")
        observed = {hint.name for hint in hints}
        if observed != expected_names or len(hints) != len(expected_names):
            raise ProjectionFailure("projection generation inventory is not exact")

    def _create_or_verify(
        self,
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
                raise ProjectionFailure("content-addressed projection conflicts") from None
            return
        if created.bytes != payload:
            raise ProjectionFailure("created projection differs from verified bytes")

    @staticmethod
    def _read_current_if_present(
        workspace: SecureWorkspace,
        current_relative: str,
    ) -> tuple[ProjectionCurrentPointer, bytes] | None:
        try:
            snapshot = workspace.read_verified(
                current_relative,
                max_bytes=_MAX_CURRENT_POINTER_BYTES,
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "FILE_MISSING":
                return None
            raise
        try:
            pointer = ProjectionCurrentPointer.model_validate_json(snapshot.bytes)
        except ValidationError:
            raise ProjectionFailure("existing current projection pointer is invalid") from None
        if canonical_bytes(pointer.model_dump(mode="json")) != snapshot.bytes:
            raise ProjectionFailure("existing current projection pointer is not canonical")
        return pointer, snapshot.bytes

    def _result(
        self,
        run_id: str,
        manifest: ProjectionGenerationManifest,
        manifest_relative: str,
        documents: tuple[_ProjectionDocument, ...],
    ) -> ProjectionResult:
        generation_directory = (
            self._output_root / run_id / "projections" / "generations" / manifest.generation_id
        )
        by_kind = {
            kind: tuple(
                generation_directory / document.relative_path
                for document in documents
                if document.kind == kind
            )
            for kind in ProjectionArtifactKind
        }
        return ProjectionResult(
            run_directory=generation_directory,
            generation_id=manifest.generation_id,
            current_pointer_path=self._output_root / run_id / "projections" / "current.json",
            manifest_path=self._output_root / Path(manifest_relative),
            events_path=by_kind[ProjectionArtifactKind.EVENTS_JSONL][0],
            audit_path=by_kind[ProjectionArtifactKind.AUDIT_JSONL][0],
            case_paths=by_kind[ProjectionArtifactKind.CASE_JSON],
            pack_paths=by_kind[ProjectionArtifactKind.PACK_JSON],
        )

    @staticmethod
    def _read(operation: Callable[[], _ReadResult]) -> _ReadResult:
        try:
            return operation()
        except ContractViolation as exc:
            raise ProjectionFailure(f"authoritative repository snapshot is invalid: {exc}") from exc

    @staticmethod
    def _verify_audit(
        run_id: str,
        audit_entries: tuple[AuditEntry, ...],
        head: AuditHead,
    ) -> None:
        report = validate_audit_chain(
            audit_entries,
            expected_run_id=run_id,
            expected_manifest_id=head.manifest_id,
            expected_head_sequence=head.sequence,
            expected_head_hash=head.entry_hash,
        )
        if not report.passed:
            raise ProjectionFailure(
                "authoritative audit chain is invalid at sequence "
                f"{report.failure_sequence}: {report.failure_reason}"
            )

    def _run_directory(
        self,
        run_id: str,
        target_directory: str | Path | None,
    ) -> Path:
        expected = self._output_root / run_id
        if target_directory is not None and Path(target_directory).absolute() != expected:
            raise ProjectionFailure(
                "target_directory must be the canonical run directory below output_root"
            )
        return expected

    def _atomic_write(
        self,
        workspace: SecureWorkspace,
        relative_path: str,
        payload: bytes,
        *,
        jsonl: bool,
    ) -> None:
        name = relative_path.rsplit("/", maxsplit=1)[-1]
        parent = relative_path.rsplit("/", maxsplit=1)[0]
        temporary_relative = f"{parent}/.{name}.{uuid4().hex}.tmp"
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        temporary_exists = False
        failure: ProjectionFailure | None = None
        try:
            created = workspace.create_new(temporary_relative, payload, expected_sha256)
            temporary_exists = True
            if created.bytes != payload:
                raise ProjectionFailure("temporary projection bytes changed after fsync")
            if jsonl:
                _verify_jsonl(created.bytes)
            else:
                _verify_json(created.bytes)
            installed = workspace.replace_verified(
                temporary_relative,
                relative_path,
                expected_sha256,
            )
            temporary_exists = False
            if installed.bytes != payload:
                raise ProjectionFailure("installed projection differs from verified bytes")
        except ProjectionFailure as exc:
            failure = exc
        except Exception as exc:
            failure = ProjectionFailure(f"failed to publish {name}")
            failure.__cause__ = exc
        if temporary_exists:
            try:
                workspace.delete_verified_temporary(temporary_relative, expected_sha256)
            except PathBoundaryViolation as error:
                if error.reason_code != "FILE_MISSING":
                    raise ProjectionFailure(
                        f"failed to clean temporary projection for {name}"
                    ) from error
        if failure is not None:
            raise failure

    def _fault(self, phase: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(phase)


def _document_fault_phase(document: _ProjectionDocument) -> str:
    if document.kind == ProjectionArtifactKind.EVENTS_JSONL:
        return "after_generation_events"
    if document.kind == ProjectionArtifactKind.AUDIT_JSONL:
        return "after_generation_audit"
    if document.kind == ProjectionArtifactKind.CASE_JSON:
        return f"after_generation_case:{document.projection_id}"
    return f"after_generation_pack:{document.projection_id}"


def event_case_id(event_id: str) -> str:
    """Derive a case identifier without accepting a path-shaped repository key."""

    from labcourt.contracts.events import derive_case_id

    return derive_case_id(event_id)


def _require_case_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError:
        raise ProjectionFailure("unsafe case_id for projection") from None
    if str(parsed) != value:
        raise ProjectionFailure("unsafe case_id for projection")
    return value


def _require_pack_id(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ProjectionFailure("unsafe pack_id for projection")
    return value


def _jsonl_bytes(documents: tuple[dict[str, object], ...]) -> bytes:
    return b"".join(canonical_bytes(document) + b"\n" for document in documents)


def _verify_json(payload: bytes) -> None:
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ProjectionFailure("JSON projection must not contain a UTF-8 BOM")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProjectionFailure("projection is not valid UTF-8 JSON") from None
    if canonical_bytes(value) != payload:
        raise ProjectionFailure("JSON projection is not canonical LCJ-1")


def _verify_jsonl(payload: bytes) -> None:
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ProjectionFailure("JSONL projection must not contain a UTF-8 BOM")
    if payload and not payload.endswith(b"\n"):
        raise ProjectionFailure("JSONL projection must end with LF")
    rebuilt = bytearray()
    for line in payload.splitlines():
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProjectionFailure("projection contains an invalid JSONL record") from None
        rebuilt.extend(canonical_bytes(value))
        rebuilt.extend(b"\n")
    if bytes(rebuilt) != payload:
        raise ProjectionFailure("JSONL projection is not canonical LCJ-1 with LF endings")


__all__ = [
    "MAX_PROJECTION_BYTES",
    "JsonProjector",
    "ProjectionFailure",
    "ProjectionResult",
]
