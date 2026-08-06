"""Independent, read-only validation of the selected M4 JSON generation."""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_bytes, canonical_json
from labcourt.contracts.m4_artifact_validation import (
    M4ArtifactValidationArea,
    M4ArtifactValidationBudget,
    M4ArtifactValidationIssue,
    M4ArtifactValidationIssueCode,
)
from labcourt.contracts.m4_projection import (
    M4ProjectionArtifactKind,
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationEntry,
    M4ProjectionGenerationManifest,
    m4_projection_relative_path,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import (
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    PathBoundaryViolation,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class M4ProjectionArtifactSnapshot(Protocol):
    @property
    def size_bytes(self) -> int: ...

    @property
    def sha256(self) -> str: ...

    @property
    def bytes(self) -> bytes: ...


class M4ProjectionDirectoryHint(Protocol):
    @property
    def name(self) -> str | None: ...

    @property
    def source_token(self) -> str: ...

    @property
    def reason_code(self) -> str | None: ...


class M4ProjectionArtifactReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> M4ProjectionArtifactSnapshot: ...

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[M4ProjectionDirectoryHint, ...]: ...


class M4ProjectionAuthorityDocument(Protocol):
    @property
    def kind(self) -> M4ProjectionArtifactKind: ...

    @property
    def artifact_id(self) -> str: ...

    @property
    def canonical_document(self) -> str: ...

    @property
    def document_sha256(self) -> str: ...


class M4ProjectionAuthoritySnapshot(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def documents(self) -> Sequence[M4ProjectionAuthorityDocument]: ...

    @property
    def authority_root_sha256(self) -> str: ...


@dataclass(frozen=True, slots=True)
class M4CurrentProjectionValidation:
    projection_files: int
    projection_documents: int
    projection_bytes: int
    max_projection_file_bytes: int
    projected_by_kind: tuple[tuple[M4ProjectionArtifactKind, int], ...]
    issues: tuple[M4ArtifactValidationIssue, ...]


@dataclass(slots=True)
class _Observation:
    budget: M4ArtifactValidationBudget
    issues: list[M4ArtifactValidationIssue] = field(default_factory=list)
    read_sizes: dict[str, int] = field(default_factory=dict)
    physical_files: set[str] = field(default_factory=set)
    projected: Counter[M4ProjectionArtifactKind] = field(default_factory=Counter)

    @property
    def bytes_read(self) -> int:
        return sum(self.read_sizes.values())

    def result(self) -> M4CurrentProjectionValidation:
        projected_by_kind = tuple((kind, self.projected[kind]) for kind in M4ProjectionArtifactKind)
        unique = {issue.sort_key: issue for issue in self.issues}
        issues = tuple(unique[key] for key in sorted(unique))
        return M4CurrentProjectionValidation(
            projection_files=len(self.physical_files),
            projection_documents=sum(self.projected.values()),
            projection_bytes=self.bytes_read,
            max_projection_file_bytes=max(self.read_sizes.values(), default=0),
            projected_by_kind=projected_by_kind,
            issues=issues,
        )


@dataclass(frozen=True, slots=True)
class _ExpectedProjection:
    documents: dict[tuple[M4ProjectionArtifactKind, str], bytes]
    entries: dict[tuple[M4ProjectionArtifactKind, str], M4ProjectionGenerationEntry]
    manifest: M4ProjectionGenerationManifest
    manifest_bytes: bytes
    pointer: M4ProjectionCurrentPointer
    pointer_bytes: bytes


class M4CurrentProjectionValidator:
    """Validate current.json and its complete generation without publishing."""

    __slots__ = ("_budget", "_reader")

    def __init__(
        self,
        *,
        artifact_reader: M4ProjectionArtifactReader,
        budget: M4ArtifactValidationBudget,
    ) -> None:
        self._reader = artifact_reader
        self._budget = budget

    def validate(
        self,
        run_id: str,
        authority: M4ProjectionAuthoritySnapshot,
    ) -> M4CurrentProjectionValidation:
        controlled_run_id = require_reference_token(run_id, "M4 projection validation run_id")
        if authority.run_id != controlled_run_id:
            raise ContractViolation("M4 projection validation authority belongs to another run")
        expected = _expected_projection(controlled_run_id, authority)
        observation = _Observation(self._budget)
        if self._append_expected_budget_issues(expected, observation):
            return observation.result()

        current_relative = f"{controlled_run_id}/m4-projections/current.json"
        pointer_snapshot = self._read(current_relative, observation)
        if pointer_snapshot is None:
            return observation.result()
        pointer = self._parse_pointer(current_relative, pointer_snapshot, observation)
        if pointer is None:
            return observation.result()

        expected_pointer_sha = _sha256(expected.pointer_bytes)
        if pointer.run_id != controlled_run_id:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
                    current_relative,
                    "POINTER_RUN_MISMATCH",
                    expected_sha256=expected_pointer_sha,
                    actual_sha256=pointer_snapshot.sha256,
                    expected_size_bytes=len(expected.pointer_bytes),
                    actual_size_bytes=pointer_snapshot.size_bytes,
                )
            )
            return observation.result()
        if (
            pointer.authority_root_sha256 != authority.authority_root_sha256
            or pointer.generation_id != expected.manifest.generation_id
        ):
            reason = (
                "POINTER_AUTHORITY_ROOT_MISMATCH"
                if pointer.authority_root_sha256 != authority.authority_root_sha256
                else "POINTER_GENERATION_MISMATCH"
            )
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
                    current_relative,
                    reason,
                    expected_sha256=expected_pointer_sha,
                    actual_sha256=pointer_snapshot.sha256,
                    expected_size_bytes=len(expected.pointer_bytes),
                    actual_size_bytes=pointer_snapshot.size_bytes,
                )
            )
        elif pointer_snapshot.bytes != expected.pointer_bytes:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    current_relative,
                    "POINTER_CONTENT_MISMATCH",
                    expected_sha256=expected_pointer_sha,
                    actual_sha256=pointer_snapshot.sha256,
                    expected_size_bytes=len(expected.pointer_bytes),
                    actual_size_bytes=pointer_snapshot.size_bytes,
                )
            )

        manifest_snapshot = self._read(pointer.manifest_relative_path, observation)
        if manifest_snapshot is None:
            return observation.result()
        manifest = self._parse_manifest(
            pointer.manifest_relative_path,
            manifest_snapshot,
            observation,
        )
        if manifest is None:
            return observation.result()
        for entry in manifest.entries:
            observation.projected[entry.kind] += 1

        if (
            manifest_snapshot.sha256 != pointer.manifest_sha256
            or manifest_snapshot.size_bytes != pointer.manifest_size_bytes
        ):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    pointer.manifest_relative_path,
                    "MANIFEST_POINTER_RECEIPT_MISMATCH",
                    expected_sha256=pointer.manifest_sha256,
                    actual_sha256=manifest_snapshot.sha256,
                    expected_size_bytes=pointer.manifest_size_bytes,
                    actual_size_bytes=manifest_snapshot.size_bytes,
                )
            )
        if (
            manifest.run_id != controlled_run_id
            or manifest.run_id != pointer.run_id
            or manifest.authority_root_sha256 != pointer.authority_root_sha256
            or manifest.generation_id != pointer.generation_id
        ):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_ROOT_MISMATCH,
                    pointer.manifest_relative_path,
                    "MANIFEST_ROOT_BINDING_MISMATCH",
                    expected_sha256=_sha256(expected.manifest_bytes),
                    actual_sha256=manifest_snapshot.sha256,
                    expected_size_bytes=len(expected.manifest_bytes),
                    actual_size_bytes=manifest_snapshot.size_bytes,
                )
            )
            if manifest.run_id != controlled_run_id:
                return observation.result()
        elif manifest_snapshot.bytes != expected.manifest_bytes:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    pointer.manifest_relative_path,
                    "MANIFEST_AUTHORITY_MISMATCH",
                    expected_sha256=_sha256(expected.manifest_bytes),
                    actual_sha256=manifest_snapshot.sha256,
                    expected_size_bytes=len(expected.manifest_bytes),
                    actual_size_bytes=manifest_snapshot.size_bytes,
                )
            )

        actual_entries = {(entry.kind, entry.artifact_id): entry for entry in manifest.entries}
        self._append_manifest_inventory_issues(
            pointer.manifest_relative_path,
            expected.entries,
            actual_entries,
            observation,
        )
        generation_relative = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[0]
        for identity, expected_entry in expected.entries.items():
            actual_entry = actual_entries.get(identity)
            if actual_entry is None:
                continue
            document_relative = f"{generation_relative}/{actual_entry.relative_path}"
            if actual_entry != expected_entry:
                observation.issues.append(
                    _projection_issue(
                        M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                        document_relative,
                        "DOCUMENT_MANIFEST_RECEIPT_MISMATCH",
                        inventory_kind=expected_entry.kind,
                        artifact_id=expected_entry.artifact_id,
                        expected_sha256=expected_entry.sha256,
                        actual_sha256=actual_entry.sha256,
                        expected_size_bytes=expected_entry.size_bytes,
                        actual_size_bytes=actual_entry.size_bytes,
                    )
                )
            document_snapshot = self._read(document_relative, observation)
            if document_snapshot is None:
                continue
            expected_bytes = expected.documents[identity]
            if document_snapshot.bytes != expected_bytes:
                observation.issues.append(
                    _projection_issue(
                        M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                        document_relative,
                        "DOCUMENT_CONTENT_MISMATCH",
                        inventory_kind=expected_entry.kind,
                        artifact_id=expected_entry.artifact_id,
                        expected_sha256=expected_entry.sha256,
                        actual_sha256=document_snapshot.sha256,
                        expected_size_bytes=expected_entry.size_bytes,
                        actual_size_bytes=document_snapshot.size_bytes,
                    )
                )
            elif (
                document_snapshot.sha256 != actual_entry.sha256
                or document_snapshot.size_bytes != actual_entry.size_bytes
            ):
                observation.issues.append(
                    _projection_issue(
                        M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                        document_relative,
                        "DOCUMENT_MANIFEST_CONTENT_MISMATCH",
                        inventory_kind=expected_entry.kind,
                        artifact_id=expected_entry.artifact_id,
                        expected_sha256=actual_entry.sha256,
                        actual_sha256=document_snapshot.sha256,
                        expected_size_bytes=actual_entry.size_bytes,
                        actual_size_bytes=document_snapshot.size_bytes,
                    )
                )

        self._validate_exact_inventory(generation_relative, pointer, manifest, observation)
        if len(observation.physical_files) > self._budget.max_projection_files:
            observation.issues.append(
                _budget_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_FILE_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_projection_files,
                    len(observation.physical_files),
                )
            )
        return observation.result()

    def _append_expected_budget_issues(
        self,
        expected: _ExpectedProjection,
        observation: _Observation,
    ) -> bool:
        sizes = (
            len(expected.pointer_bytes),
            len(expected.manifest_bytes),
            *(len(payload) for payload in expected.documents.values()),
        )
        checks = (
            (
                M4ArtifactValidationIssueCode.PROJECTION_FILE_COUNT_BUDGET_EXCEEDED,
                self._budget.max_projection_files,
                len(sizes),
            ),
            (
                M4ArtifactValidationIssueCode.PROJECTION_FILE_BYTES_BUDGET_EXCEEDED,
                self._budget.max_projection_file_bytes,
                max(sizes, default=0),
            ),
            (
                M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED,
                self._budget.max_projection_total_bytes,
                sum(sizes),
            ),
        )
        observation.issues.extend(
            _budget_issue(code, limit, observed)
            for code, limit, observed in checks
            if observed > limit
        )
        return bool(observation.issues)

    def _read(
        self,
        relative_path: str,
        observation: _Observation,
    ) -> M4ProjectionArtifactSnapshot | None:
        remaining = self._budget.max_projection_total_bytes - observation.bytes_read
        if remaining <= 0:
            observation.issues.append(
                _budget_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_projection_total_bytes,
                    self._budget.max_projection_total_bytes + 1,
                )
            )
            return None
        read_limit = min(self._budget.max_projection_file_bytes, remaining)
        try:
            snapshot = self._reader.read_verified(relative_path, max_bytes=read_limit)
        except BudgetExceeded:
            if remaining < self._budget.max_projection_file_bytes:
                code = M4ArtifactValidationIssueCode.PROJECTION_TOTAL_BYTES_BUDGET_EXCEEDED
                limit = self._budget.max_projection_total_bytes
            else:
                code = M4ArtifactValidationIssueCode.PROJECTION_FILE_BYTES_BUDGET_EXCEEDED
                limit = self._budget.max_projection_file_bytes
            observation.issues.append(_budget_issue(code, limit, limit + 1))
            return None
        except PathBoundaryViolation as error:
            code = (
                M4ArtifactValidationIssueCode.PROJECTION_MISSING
                if error.reason_code in {"FILE_MISSING", "DIRECTORY_MISSING"}
                else M4ArtifactValidationIssueCode.PROJECTION_UNSAFE
            )
            observation.issues.append(_projection_issue(code, relative_path, error.reason_code))
            return None
        except ArtifactIntegrityViolation:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    relative_path,
                    "ARTIFACT_INTEGRITY_FAILURE",
                )
            )
            return None
        except (AttributeError, TypeError, ValueError):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                    relative_path,
                    "PROJECTION_READER_REJECTED",
                )
            )
            return None
        try:
            payload = snapshot.bytes
            if not isinstance(payload, bytes):
                raise TypeError
            size = len(payload)
            digest = _sha256(payload)
            if (
                not isinstance(snapshot.size_bytes, int)
                or isinstance(snapshot.size_bytes, bool)
                or snapshot.size_bytes != size
                or snapshot.sha256 != digest
                or size > read_limit
            ):
                raise ValueError
        except (AttributeError, TypeError, ValueError):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                    relative_path,
                    "PROJECTION_READER_RECEIPT_MISMATCH",
                )
            )
            return None
        observation.read_sizes[relative_path] = size
        observation.physical_files.add(relative_path)
        return snapshot

    @staticmethod
    def _parse_pointer(
        relative_path: str,
        snapshot: M4ProjectionArtifactSnapshot,
        observation: _Observation,
    ) -> M4ProjectionCurrentPointer | None:
        try:
            pointer = M4ProjectionCurrentPointer.model_validate_json(snapshot.bytes)
        except ValidationError:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    relative_path,
                    "POINTER_CONTRACT_INVALID",
                )
            )
            return None
        if canonical_bytes(pointer.model_dump(mode="json")) != snapshot.bytes:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    relative_path,
                    "POINTER_NOT_CANONICAL",
                )
            )
        return pointer

    @staticmethod
    def _parse_manifest(
        relative_path: str,
        snapshot: M4ProjectionArtifactSnapshot,
        observation: _Observation,
    ) -> M4ProjectionGenerationManifest | None:
        try:
            manifest = M4ProjectionGenerationManifest.model_validate_json(snapshot.bytes)
        except ValidationError:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    relative_path,
                    "MANIFEST_CONTRACT_INVALID",
                )
            )
            return None
        if canonical_bytes(manifest.model_dump(mode="json")) != snapshot.bytes:
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                    relative_path,
                    "MANIFEST_NOT_CANONICAL",
                )
            )
        return manifest

    @staticmethod
    def _append_manifest_inventory_issues(
        source_path: str,
        expected: dict[tuple[M4ProjectionArtifactKind, str], M4ProjectionGenerationEntry],
        actual: dict[tuple[M4ProjectionArtifactKind, str], M4ProjectionGenerationEntry],
        observation: _Observation,
    ) -> None:
        expected_counts = Counter(identity[0] for identity in expected)
        actual_counts = Counter(identity[0] for identity in actual)
        for kind in M4ProjectionArtifactKind:
            if expected_counts[kind] == actual_counts[kind]:
                continue
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH,
                    source_path,
                    "MANIFEST_INVENTORY_MISMATCH",
                    inventory_kind=kind,
                    authoritative_count=expected_counts[kind],
                    projected_count=actual_counts[kind],
                )
            )

    def _validate_exact_inventory(
        self,
        generation_relative: str,
        pointer: M4ProjectionCurrentPointer,
        manifest: M4ProjectionGenerationManifest,
        observation: _Observation,
    ) -> None:
        manifest_name = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[-1]
        generation_names = self._list(
            generation_relative,
            {"documents", manifest_name},
            observation,
        )
        for name in generation_names:
            if name != "documents":
                observation.physical_files.add(f"{generation_relative}/{name}")

        by_directory: dict[str, set[str]] = defaultdict(set)
        for entry in manifest.entries:
            directory, name = entry.relative_path.rsplit("/", maxsplit=1)
            by_directory[directory.split("/", maxsplit=1)[1]].add(name)
        documents_relative = f"{generation_relative}/documents"
        directory_names = self._list(
            documents_relative,
            set(by_directory),
            observation,
        )
        for directory in sorted(set(by_directory) | directory_names):
            names = self._list(
                f"{documents_relative}/{directory}",
                by_directory.get(directory, set()),
                observation,
            )
            observation.physical_files.update(
                f"{documents_relative}/{directory}/{name}" for name in names
            )

    def _list(
        self,
        relative_path: str,
        expected_names: set[str],
        observation: _Observation,
    ) -> set[str]:
        try:
            hints = self._reader.list_projection_directory(
                relative_path,
                self._budget.max_projection_files + 1,
                self._budget.max_projection_name_bytes,
            )
        except BudgetExceeded:
            observation.issues.append(
                _budget_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_FILE_COUNT_BUDGET_EXCEEDED,
                    self._budget.max_projection_files,
                    self._budget.max_projection_files + 1,
                )
            )
            return set()
        except PathBoundaryViolation as error:
            code = (
                M4ArtifactValidationIssueCode.PROJECTION_MISSING
                if error.reason_code == "DIRECTORY_MISSING"
                else M4ArtifactValidationIssueCode.PROJECTION_UNSAFE
            )
            observation.issues.append(_projection_issue(code, relative_path, error.reason_code))
            return set()
        except (AttributeError, TypeError, ValueError):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                    relative_path,
                    "INVENTORY_READER_REJECTED",
                )
            )
            return set()
        observed: set[str] = set()
        for hint in hints:
            try:
                name = hint.name
                source_token = hint.source_token
                reason_code = hint.reason_code
            except AttributeError:
                name = None
                source_token = _source_token(relative_path)
                reason_code = "INVALID_ENTRY_NAME"
            if (
                name is None
                or not isinstance(name, str)
                or name in {"", ".", ".."}
                or "/" in name
                or "\\" in name
                or reason_code is not None
                or not isinstance(source_token, str)
                or _SHA256.fullmatch(source_token) is None
            ):
                observation.issues.append(
                    M4ArtifactValidationIssue(
                        code=M4ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                        area=M4ArtifactValidationArea.PROJECTION,
                        source_token=(
                            source_token
                            if isinstance(source_token, str)
                            and _SHA256.fullmatch(source_token) is not None
                            else _source_token(relative_path)
                        ),
                        reason_code=(
                            reason_code
                            if isinstance(reason_code, str)
                            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", reason_code)
                            else "INVALID_ENTRY_NAME"
                        ),
                    )
                )
                continue
            observed.add(name)
        if observed != expected_names or len(hints) != len(expected_names):
            observation.issues.append(
                _projection_issue(
                    M4ArtifactValidationIssueCode.PROJECTION_INVENTORY_MISMATCH,
                    relative_path,
                    "EXACT_INVENTORY_MISMATCH",
                )
            )
        return observed


def _expected_projection(
    run_id: str,
    authority: M4ProjectionAuthoritySnapshot,
) -> _ExpectedProjection:
    documents: dict[tuple[M4ProjectionArtifactKind, str], bytes] = {}
    entries: dict[tuple[M4ProjectionArtifactKind, str], M4ProjectionGenerationEntry] = {}
    for document in authority.documents:
        if not isinstance(document.kind, M4ProjectionArtifactKind):
            raise ContractViolation("M4 authority returned an unknown projection kind")
        identity = (document.kind, document.artifact_id)
        try:
            payload = document.canonical_document.encode("utf-8")
        except (AttributeError, UnicodeEncodeError):
            raise ContractViolation("M4 authority returned invalid projection bytes") from None
        if identity in documents or _sha256(payload) != document.document_sha256:
            raise ContractViolation("M4 authority returned invalid projection documents")
        documents[identity] = payload
        entries[identity] = M4ProjectionGenerationEntry(
            kind=document.kind,
            artifact_id=document.artifact_id,
            relative_path=m4_projection_relative_path(document.kind, document.artifact_id),
            sha256=document.document_sha256,
            size_bytes=len(payload),
        )
    manifest = M4ProjectionGenerationManifest(
        run_id=run_id,
        authority_root_sha256=authority.authority_root_sha256,
        entries=tuple(sorted(entries.values(), key=lambda item: item.sort_key)),
    )
    manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
    manifest_sha256 = _sha256(manifest_bytes)
    manifest_relative = (
        f"{run_id}/m4-projections/generations/{manifest.generation_id}/"
        f"manifest-{manifest_sha256}.json"
    )
    pointer = M4ProjectionCurrentPointer(
        run_id=run_id,
        authority_root_sha256=authority.authority_root_sha256,
        generation_id=manifest.generation_id,
        manifest_relative_path=manifest_relative,
        manifest_sha256=manifest_sha256,
        manifest_size_bytes=len(manifest_bytes),
    )
    return _ExpectedProjection(
        documents=documents,
        entries=entries,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        pointer=pointer,
        pointer_bytes=canonical_bytes(pointer.model_dump(mode="json")),
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _source_token(relative_path: str) -> str:
    return _sha256(canonical_json(["m4-artifact-source", 1, relative_path]).encode("utf-8"))


def _projection_issue(
    code: M4ArtifactValidationIssueCode,
    source_path: str,
    reason_code: str,
    *,
    inventory_kind: M4ProjectionArtifactKind | None = None,
    artifact_id: str | None = None,
    authoritative_count: int | None = None,
    projected_count: int | None = None,
    expected_sha256: str | None = None,
    actual_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    actual_size_bytes: int | None = None,
) -> M4ArtifactValidationIssue:
    return M4ArtifactValidationIssue(
        code=code,
        area=M4ArtifactValidationArea.PROJECTION,
        inventory_kind=inventory_kind,
        artifact_id=artifact_id,
        source_token=_source_token(source_path),
        reason_code=reason_code,
        authoritative_count=authoritative_count,
        projected_count=projected_count,
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        expected_size_bytes=expected_size_bytes,
        actual_size_bytes=actual_size_bytes,
    )


def _budget_issue(
    code: M4ArtifactValidationIssueCode,
    limit: int,
    observed: int,
) -> M4ArtifactValidationIssue:
    return M4ArtifactValidationIssue(
        code=code,
        area=M4ArtifactValidationArea.BUDGET,
        limit=limit,
        observed=observed,
    )


__all__ = [
    "M4CurrentProjectionValidation",
    "M4CurrentProjectionValidator",
    "M4ProjectionArtifactReader",
    "M4ProjectionAuthoritySnapshot",
]
