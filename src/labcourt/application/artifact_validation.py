"""Read-only, bounded validation of authoritative M2 artifacts and projections."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from labcourt.contracts.artifact_validation import (
    ArtifactInventoryKind,
    ArtifactValidationArea,
    ArtifactValidationBudget,
    ArtifactValidationCounts,
    ArtifactValidationIssue,
    ArtifactValidationIssueCode,
    ArtifactValidationReport,
    M3ArtifactInventoryKind,
    M3ArtifactValidationArea,
    M3ArtifactValidationBudget,
    M3ArtifactValidationCounts,
    M3ArtifactValidationIssue,
    M3ArtifactValidationIssueCode,
    M3ArtifactValidationReport,
    ProjectionArtifactKind,
)
from labcourt.contracts.audit import AuditEntry, validate_audit_chain
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, MediaAvailability
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.projection_generation import (
    ProjectionCurrentPointer,
    ProjectionGenerationEntry,
    ProjectionGenerationManifest,
)
from labcourt.contracts.recovery import recovery_source_token
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import VLMResponse
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.exceptions import (
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ContractViolation,
    PathBoundaryViolation,
)
from labcourt.ports.evidence_repository import AuditHead, EvidenceRepository


class ArtifactSnapshot(Protocol):
    @property
    def size_bytes(self) -> int: ...

    @property
    def sha256(self) -> str: ...

    @property
    def bytes(self) -> bytes: ...


class ArtifactReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> ArtifactSnapshot: ...

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[ProjectionDirectoryHint, ...]: ...


class ProjectionDirectoryHint(Protocol):
    @property
    def name(self) -> str | None: ...

    @property
    def source_token(self) -> str: ...

    @property
    def reason_code(self) -> str | None: ...


class M3ArtifactReader(Protocol):
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> ArtifactSnapshot: ...

    def list_model_response_recovery_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[M3DirectoryHint, ...]: ...

    def inspect_verified(self, relative_path: str) -> M3FileMetadata: ...


class M3DirectoryHint(Protocol):
    @property
    def name(self) -> str | None: ...

    @property
    def source_token(self) -> str: ...

    @property
    def reason_code(self) -> str | None: ...


class M3FileMetadata(Protocol):
    @property
    def relative_path(self) -> str: ...

    @property
    def size_bytes(self) -> int: ...

    @property
    def identity_token(self) -> str: ...


class M3AuthorityFailureObservation(Protocol):
    @property
    def failure_type(self) -> str: ...

    @property
    def inventory_kind(self) -> M3ArtifactInventoryKind: ...

    @property
    def record_identity_sha256(self) -> str: ...

    @property
    def artifact_id(self) -> str | None: ...

    @property
    def reason_code(self) -> str: ...


class M3RawResponseObservation(Protocol):
    @property
    def response(self) -> VLMResponse: ...

    @property
    def record_identity_sha256(self) -> str: ...


class M3TraversedObservation(Protocol):
    @property
    def inventory_kind(self) -> M3ArtifactInventoryKind: ...

    @property
    def count(self) -> int: ...


class M3AuthoritySnapshot(Protocol):
    @property
    def traversed(self) -> tuple[M3TraversedObservation, ...]: ...

    @property
    def raw_responses(self) -> tuple[M3RawResponseObservation, ...]: ...

    @property
    def failures(self) -> tuple[M3AuthorityFailureObservation, ...]: ...


class M3ArtifactAuthorityReader(Protocol):
    def scan(self, run_id: str) -> M3AuthoritySnapshot: ...


@dataclass(frozen=True, slots=True)
class _ProjectionExpectation:
    kind: ProjectionArtifactKind
    projection_id: str
    relative_path: str
    expected_bytes: bytes


@dataclass(frozen=True, slots=True)
class _ProjectionInventoryExpectation:
    relative_directory: str
    expected_names: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ResolvedProjection:
    expectations: tuple[_ProjectionExpectation, ...]
    inventories: tuple[_ProjectionInventoryExpectation, ...]
    metadata_bytes: int


_MAX_CURRENT_POINTER_BYTES = 4 * 1024


def _generation_document_relative(
    kind: ProjectionArtifactKind,
    projection_id: str,
) -> str:
    if kind == ProjectionArtifactKind.EVENTS_JSONL:
        return "events.jsonl"
    if kind == ProjectionArtifactKind.AUDIT_JSONL:
        return "audit.jsonl"
    if kind == ProjectionArtifactKind.CASE_JSON:
        return f"cases/{projection_id}.json"
    return f"packs/{projection_id}.json"


class ArtifactValidator:
    """Validate one run without repairing, projecting, or changing authority state."""

    __slots__ = ("_authority_counts", "_budget", "_reader", "_repository")

    def __init__(
        self,
        *,
        repository: EvidenceRepository,
        artifact_reader: ArtifactReader,
        authority_counts: ArtifactValidationCounts,
        budget: ArtifactValidationBudget | None = None,
    ) -> None:
        if not isinstance(authority_counts, ArtifactValidationCounts):
            raise TypeError("authority_counts must be ArtifactValidationCounts")
        self._repository = repository
        self._reader = artifact_reader
        self._budget = budget or ArtifactValidationBudget()
        self._authority_counts = authority_counts

    def validate(self, run_id: str) -> ArtifactValidationReport:
        run_id = require_reference_token(run_id, "artifact validator run_id")
        issues: list[ArtifactValidationIssue] = []
        try:
            head = self._repository.get_audit_head(run_id)
        except (ContractViolation, TypeError, ValueError):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
                    area=ArtifactValidationArea.AUTHORITY,
                )
            )
            return self._report(
                run_id,
                None,
                self._reported_counts(),
                issues,
            )

        audit_entries = self._audit_entries(run_id, head, issues)
        audit_count = len(audit_entries) if audit_entries is not None else 0
        if audit_entries is not None and audit_count > self._budget.max_audit_entries:
            issues.append(
                self._budget_issue(
                    ArtifactValidationIssueCode.AUDIT_BUDGET_EXCEEDED,
                    self._budget.max_audit_entries,
                    audit_count,
                )
            )
            audit_entries = None
        events = self._events(run_id, head, issues)
        event_count = len(events) if events is not None else 0
        if events is not None and event_count > self._budget.max_events:
            issues.append(
                self._budget_issue(
                    ArtifactValidationIssueCode.EVENT_BUDGET_EXCEEDED,
                    self._budget.max_events,
                    event_count,
                )
            )
            events = None

        cases: tuple[Case, ...] = ()
        if events is not None:
            if len(events) > self._budget.max_cases:
                issues.append(
                    self._budget_issue(
                        ArtifactValidationIssueCode.CASE_BUDGET_EXCEEDED,
                        self._budget.max_cases,
                        len(events),
                    )
                )
            else:
                cases = self._cases(run_id, head, events, issues)

        embedded_packs = tuple(pack for case in cases for pack in case.evidence_packs)
        pack_count = len(embedded_packs)
        media_ids = {crop.media_sha256 for pack in embedded_packs for crop in pack.crops}
        if pack_count > self._budget.max_packs:
            issues.append(
                self._budget_issue(
                    ArtifactValidationIssueCode.PACK_BUDGET_EXCEEDED,
                    self._budget.max_packs,
                    pack_count,
                )
            )
        if len(media_ids) > self._budget.max_media:
            issues.append(
                self._budget_issue(
                    ArtifactValidationIssueCode.MEDIA_BUDGET_EXCEEDED,
                    self._budget.max_media,
                    len(media_ids),
                )
            )
        if pack_count > self._budget.max_packs or len(media_ids) > self._budget.max_media:
            packs: tuple[EvidencePack, ...] = ()
        else:
            packs = self._packs(run_id, head, embedded_packs, issues)

        projections = 0
        projection_bytes = 0
        if (
            events is not None
            and audit_entries is not None
            and len(media_ids) <= self._budget.max_media
            and pack_count <= self._budget.max_packs
            and len(cases) == len(events)
            and len(packs) == pack_count
        ):
            expectations, projected_size = self._projection_expectations(
                run_id,
                events,
                audit_entries,
                cases,
                packs,
            )
            if expectations is None:
                issues.append(
                    self._budget_issue(
                        ArtifactValidationIssueCode.PROJECTION_BYTES_BUDGET_EXCEEDED,
                        self._budget.max_projection_bytes,
                        projected_size,
                    )
                )
            else:
                projections, projection_bytes = self._validate_projections(
                    run_id,
                    head,
                    expectations,
                    issues,
                )

        traversed_counts = ArtifactValidationCounts(
            audit_entries=audit_count,
            events=event_count,
            cases=len(cases),
            packs=pack_count,
            media=len(media_ids),
        )
        self._append_inventory_issues(traversed_counts, issues)
        return self._report(
            run_id,
            head,
            self._reported_counts(
                projections=projections,
                projection_bytes=projection_bytes,
            ),
            issues,
        )

    def _append_inventory_issues(
        self,
        traversed: ArtifactValidationCounts,
        issues: list[ArtifactValidationIssue],
    ) -> None:
        inventories = (
            (
                ArtifactInventoryKind.AUDIT_ENTRY,
                ArtifactValidationArea.AUDIT,
                self._authority_counts.audit_entries,
                traversed.audit_entries,
            ),
            (
                ArtifactInventoryKind.EVENT,
                ArtifactValidationArea.EVENT,
                self._authority_counts.events,
                traversed.events,
            ),
            (
                ArtifactInventoryKind.CASE,
                ArtifactValidationArea.CASE,
                self._authority_counts.cases,
                traversed.cases,
            ),
            (
                ArtifactInventoryKind.PACK,
                ArtifactValidationArea.PACK,
                self._authority_counts.packs,
                traversed.packs,
            ),
            (
                ArtifactInventoryKind.MEDIA,
                ArtifactValidationArea.MEDIA,
                self._authority_counts.media,
                traversed.media,
            ),
        )
        for kind, area, authoritative_count, traversed_count in inventories:
            if authoritative_count == traversed_count:
                continue
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
                    area=area,
                    inventory_kind=kind,
                    authoritative_count=authoritative_count,
                    traversed_count=traversed_count,
                )
            )

    def _reported_counts(
        self,
        *,
        projections: int = 0,
        projection_bytes: int = 0,
    ) -> ArtifactValidationCounts:
        return self._authority_counts.model_copy(
            update={
                "projections": projections,
                "projection_bytes": projection_bytes,
            }
        )

    def _audit_entries(
        self,
        run_id: str,
        head: AuditHead,
        issues: list[ArtifactValidationIssue],
    ) -> tuple[AuditEntry, ...] | None:
        try:
            entries = self._repository.list_audit_entries(run_id)
            if not isinstance(entries, tuple) or any(
                not isinstance(entry, AuditEntry) for entry in entries
            ):
                raise TypeError
        except (ContractViolation, TypeError, ValueError):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUDIT_DOCUMENT_INVALID,
                    area=ArtifactValidationArea.AUDIT,
                )
            )
            return None
        report = validate_audit_chain(
            entries,
            expected_run_id=run_id,
            expected_manifest_id=head.manifest_id,
            expected_head_sequence=head.sequence,
            expected_head_hash=head.entry_hash,
        )
        if not report.passed:
            assert report.failure_reason is not None
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.AUDIT_CHAIN_INVALID,
                    area=ArtifactValidationArea.AUDIT,
                    audit_failure_reason=report.failure_reason,
                    sequence=report.failure_sequence,
                )
            )
        return entries

    def _events(
        self,
        run_id: str,
        head: AuditHead,
        issues: list[ArtifactValidationIssue],
    ) -> tuple[CandidateEvent, ...] | None:
        try:
            events = self._repository.list_events(run_id)
            if not isinstance(events, tuple) or any(
                not isinstance(event, CandidateEvent) for event in events
            ):
                raise TypeError
        except (ContractViolation, TypeError, ValueError):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.EVENT_DOCUMENT_INVALID,
                    area=ArtifactValidationArea.EVENT,
                )
            )
            return None
        if any(event.manifest_id != head.manifest_id for event in events):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.EVENT_DOCUMENT_INVALID,
                    area=ArtifactValidationArea.EVENT,
                    reason_code="MANIFEST_SCOPE_MISMATCH",
                )
            )
        return events

    def _cases(
        self,
        run_id: str,
        head: AuditHead,
        events: tuple[CandidateEvent, ...],
        issues: list[ArtifactValidationIssue],
    ) -> tuple[Case, ...]:
        cases: list[Case] = []
        for event in events:
            case_id = derive_case_id(event.event_id)
            case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)
            try:
                snapshot = self._repository.load_case(run_id, case_id)
                case = snapshot.case
                if not isinstance(snapshot.revision, int) or isinstance(snapshot.revision, bool):
                    raise TypeError
            except (ContractViolation, TypeError, ValueError):
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.CASE_DOCUMENT_INVALID,
                        area=ArtifactValidationArea.CASE,
                        artifact_ref=case_ref,
                    )
                )
                continue
            if (
                snapshot.revision < 1
                or case.run_id != run_id
                or case.case_id != case_id
                or case.event != event
                or case.manifest_id != head.manifest_id
            ):
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.CASE_SCOPE_MISMATCH,
                        area=ArtifactValidationArea.CASE,
                        artifact_ref=case_ref,
                    )
                )
            cases.append(case)
        return tuple(cases)

    def _packs(
        self,
        run_id: str,
        head: AuditHead,
        embedded_packs: tuple[EvidencePack, ...],
        issues: list[ArtifactValidationIssue],
    ) -> tuple[EvidencePack, ...]:
        packs: list[EvidencePack] = []
        for embedded in embedded_packs:
            pack_ref = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=embedded.pack_id)
            try:
                pack = self._repository.load_pack(run_id, embedded.pack_id)
            except (ContractViolation, TypeError, ValueError):
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.PACK_DOCUMENT_INVALID,
                        area=ArtifactValidationArea.PACK,
                        artifact_ref=pack_ref,
                    )
                )
                continue
            if (
                pack != embedded
                or pack.run_id != run_id
                or pack.case_id != embedded.case_id
                or pack.manifest_id != head.manifest_id
                or pack.event != embedded.event
            ):
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.PACK_SCOPE_MISMATCH,
                        area=ArtifactValidationArea.PACK,
                        artifact_ref=pack_ref,
                    )
                )
            packs.append(pack)
            self._current_closure(run_id, pack, pack_ref, issues)
        return tuple(packs)

    def _current_closure(
        self,
        run_id: str,
        pack: EvidencePack,
        pack_ref: ArtifactRef,
        issues: list[ArtifactValidationIssue],
    ) -> None:
        try:
            report = self._repository.verify_current_pack(run_id, pack.pack_id)
        except (ContractViolation, TypeError, ValueError):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.CURRENT_CLOSURE_INVALID,
                    area=ArtifactValidationArea.PACK,
                    root_ref=pack_ref,
                )
            )
            return
        if not self._closure_scope_matches(report, pack, pack_ref):
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.CURRENT_CLOSURE_INVALID,
                    area=ArtifactValidationArea.PACK,
                    root_ref=pack_ref,
                )
            )
            return
        for defect in report.defects:
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.CURRENT_CLOSURE_DEFECT,
                    area=ArtifactValidationArea.PACK,
                    root_ref=pack_ref,
                    artifact_ref=defect.artifact_ref or defect.related_ref,
                    closure_defect_code=defect.code,
                    reason_code=defect.reason_code,
                )
            )
        for crop in pack.crops:
            if crop.availability == MediaAvailability.AVAILABLE:
                continue
            issues.append(
                ArtifactValidationIssue(
                    code=ArtifactValidationIssueCode.MEDIA_UNAVAILABLE,
                    area=ArtifactValidationArea.MEDIA,
                    root_ref=pack_ref,
                    artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
                    media_availability=crop.availability,
                )
            )

    @staticmethod
    def _closure_scope_matches(
        report: ClosureReport,
        pack: EvidencePack,
        pack_ref: ArtifactRef,
    ) -> bool:
        if not isinstance(report, ClosureReport):
            return False
        expected = {ref.sort_key: ref for ref in pack.expected_closure_refs()}
        expected[pack_ref.sort_key] = pack_ref
        return (
            report.run_id == pack.run_id
            and report.root_ref == pack_ref
            and report.manifest_id == pack.manifest_id
            and report.input_sha256 == pack.closure_input_sha256
            and report.checked_refs == tuple(expected[key] for key in sorted(expected))
        )

    def _projection_expectations(
        self,
        run_id: str,
        events: tuple[CandidateEvent, ...],
        audit_entries: tuple[AuditEntry, ...],
        cases: tuple[Case, ...],
        packs: tuple[EvidencePack, ...],
    ) -> tuple[tuple[_ProjectionExpectation, ...] | None, int]:
        expectations: list[_ProjectionExpectation] = []
        total = 0

        def add(
            kind: ProjectionArtifactKind,
            projection_id: str,
            relative_path: str,
            expected_bytes: bytes,
        ) -> bool:
            nonlocal total
            total += len(expected_bytes)
            if total > self._budget.max_projection_bytes:
                return False
            expectations.append(
                _ProjectionExpectation(kind, projection_id, relative_path, expected_bytes)
            )
            return True

        event_bytes, event_size = self._jsonl_bytes(events, self._budget.max_projection_bytes)
        total += event_size
        if event_bytes is None or total > self._budget.max_projection_bytes:
            return None, total
        expectations.append(
            _ProjectionExpectation(
                ProjectionArtifactKind.EVENTS_JSONL,
                run_id,
                f"{run_id}/events.jsonl",
                event_bytes,
            )
        )

        audit_bytes, audit_size = self._jsonl_bytes(
            audit_entries,
            self._budget.max_projection_bytes - total,
        )
        total += audit_size
        if audit_bytes is None or total > self._budget.max_projection_bytes:
            return None, total
        expectations.append(
            _ProjectionExpectation(
                ProjectionArtifactKind.AUDIT_JSONL,
                run_id,
                f"{run_id}/audit.jsonl",
                audit_bytes,
            )
        )

        for case in sorted(cases, key=lambda value: value.case_id):
            if not add(
                ProjectionArtifactKind.CASE_JSON,
                case.case_id,
                f"{run_id}/cases/{case.case_id}.json",
                canonical_bytes(case.model_dump(mode="json")),
            ):
                return None, total
        for pack in sorted(packs, key=lambda value: value.pack_id):
            if not add(
                ProjectionArtifactKind.PACK_JSON,
                pack.pack_id,
                f"{run_id}/packs/{pack.pack_id}.json",
                canonical_bytes(pack.model_dump(mode="json")),
            ):
                return None, total
        return tuple(expectations), total

    @staticmethod
    def _jsonl_bytes(
        values: Iterable[object],
        limit: int,
    ) -> tuple[bytes | None, int]:
        chunks: list[bytes] = []
        total = 0
        for value in values:
            document = value.model_dump(mode="json")  # type: ignore[attr-defined]
            chunk = canonical_bytes(document) + b"\n"
            total += len(chunk)
            if total > limit:
                return None, total
            chunks.append(chunk)
        return b"".join(chunks), total

    def _validate_projections(
        self,
        run_id: str,
        head: AuditHead,
        expectations: tuple[_ProjectionExpectation, ...],
        issues: list[ArtifactValidationIssue],
    ) -> tuple[int, int]:
        resolved = self._resolve_current_projection(run_id, head, expectations, issues)
        if resolved is None:
            return 0, 0
        checked = 0
        total = resolved.metadata_bytes
        for expected in resolved.expectations:
            try:
                snapshot = self._reader.read_verified(
                    expected.relative_path,
                    max_bytes=len(expected.expected_bytes),
                )
            except PathBoundaryViolation as error:
                code = (
                    ArtifactValidationIssueCode.PROJECTION_MISSING
                    if error.reason_code == "FILE_MISSING"
                    else ArtifactValidationIssueCode.PROJECTION_UNSAFE
                )
                issues.append(
                    ArtifactValidationIssue(
                        code=code,
                        area=ArtifactValidationArea.PROJECTION,
                        projection_kind=expected.kind,
                        projection_id=expected.projection_id,
                        reason_code=error.reason_code,
                    )
                )
                continue
            except ArtifactIntegrityViolation:
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                        area=ArtifactValidationArea.PROJECTION,
                        projection_kind=expected.kind,
                        projection_id=expected.projection_id,
                        reason_code="ARTIFACT_INTEGRITY_FAILURE",
                    )
                )
                continue
            try:
                actual_bytes = snapshot.bytes
                if not isinstance(actual_bytes, bytes):
                    raise TypeError
                actual_size = len(actual_bytes)
                actual_sha256 = hashlib.sha256(actual_bytes).hexdigest()
                if (
                    not isinstance(snapshot.size_bytes, int)
                    or isinstance(snapshot.size_bytes, bool)
                    or snapshot.size_bytes != actual_size
                    or snapshot.sha256 != actual_sha256
                ):
                    raise ValueError
            except (AttributeError, TypeError, ValueError):
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.PROJECTION_UNSAFE,
                        area=ArtifactValidationArea.PROJECTION,
                        projection_kind=expected.kind,
                        projection_id=expected.projection_id,
                        reason_code="READER_RECEIPT_MISMATCH",
                    )
                )
                continue
            checked += 1
            total += actual_size
            if actual_bytes != expected.expected_bytes:
                issues.append(
                    ArtifactValidationIssue(
                        code=ArtifactValidationIssueCode.PROJECTION_CONTENT_MISMATCH,
                        area=ArtifactValidationArea.PROJECTION,
                        projection_kind=expected.kind,
                        projection_id=expected.projection_id,
                        expected_sha256=hashlib.sha256(expected.expected_bytes).hexdigest(),
                        actual_sha256=actual_sha256,
                        expected_size_bytes=len(expected.expected_bytes),
                        actual_size_bytes=actual_size,
                    )
                )
        inventory_failure = self._projection_inventory_failure(resolved.inventories)
        if inventory_failure is not None:
            inventory_reason, inventory_missing = inventory_failure
            self._append_release_issue(
                issues,
                expectations,
                missing=inventory_missing,
                reason_code=inventory_reason,
            )
            return 0, total
        return checked, total

    def _resolve_current_projection(
        self,
        run_id: str,
        head: AuditHead,
        expectations: tuple[_ProjectionExpectation, ...],
        issues: list[ArtifactValidationIssue],
    ) -> _ResolvedProjection | None:
        expected_entries = tuple(
            sorted(
                (
                    ProjectionGenerationEntry(
                        kind=expected.kind,
                        projection_id=expected.projection_id,
                        relative_path=_generation_document_relative(
                            expected.kind, expected.projection_id
                        ),
                        sha256=hashlib.sha256(expected.expected_bytes).hexdigest(),
                        size_bytes=len(expected.expected_bytes),
                    )
                    for expected in expectations
                ),
                key=lambda entry: entry.sort_key,
            )
        )
        expected_manifest = ProjectionGenerationManifest(
            run_id=run_id,
            audit_head_sequence=head.sequence,
            audit_head_hash=head.entry_hash,
            entries=expected_entries,
        )
        expected_manifest_bytes = canonical_bytes(expected_manifest.model_dump(mode="json"))
        expected_manifest_sha256 = hashlib.sha256(expected_manifest_bytes).hexdigest()
        expected_manifest_relative = (
            f"{run_id}/projections/generations/{expected_manifest.generation_id}/"
            f"manifest-{expected_manifest_sha256}.json"
        )
        expected_pointer = ProjectionCurrentPointer(
            run_id=run_id,
            audit_head_sequence=head.sequence,
            audit_head_hash=head.entry_hash,
            generation_id=expected_manifest.generation_id,
            manifest_relative_path=expected_manifest_relative,
            manifest_sha256=expected_manifest_sha256,
            manifest_size_bytes=len(expected_manifest_bytes),
        )
        expected_pointer_bytes = canonical_bytes(expected_pointer.model_dump(mode="json"))
        metadata_bytes = len(expected_pointer_bytes) + len(expected_manifest_bytes)
        complete_release_bytes = metadata_bytes + sum(
            len(expected.expected_bytes) for expected in expectations
        )
        if complete_release_bytes > self._budget.max_projection_bytes:
            issues.append(
                self._budget_issue(
                    ArtifactValidationIssueCode.PROJECTION_BYTES_BUDGET_EXCEEDED,
                    self._budget.max_projection_bytes,
                    complete_release_bytes,
                )
            )
            return None
        if len(expected_pointer_bytes) > _MAX_CURRENT_POINTER_BYTES:
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="EXPECTED_POINTER_LIMIT_EXCEEDED",
            )
            return None

        pointer_relative = f"{run_id}/projections/current.json"
        try:
            pointer_bytes = self._verified_reader_bytes(
                pointer_relative,
                max_bytes=min(
                    _MAX_CURRENT_POINTER_BYTES,
                    self._budget.max_projection_bytes,
                ),
            )
        except PathBoundaryViolation as error:
            self._append_release_issue(
                issues,
                expectations,
                missing=error.reason_code == "FILE_MISSING",
                reason_code=error.reason_code,
            )
            return None
        except (ArtifactIntegrityViolation, TypeError, ValueError):
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="CURRENT_POINTER_UNSAFE",
            )
            return None
        try:
            pointer = ProjectionCurrentPointer.model_validate_json(pointer_bytes)
        except ValidationError:
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="CURRENT_POINTER_INVALID",
            )
            return None
        if (
            canonical_bytes(pointer.model_dump(mode="json")) != pointer_bytes
            or pointer != expected_pointer
            or pointer_bytes != expected_pointer_bytes
        ):
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="CURRENT_POINTER_AUTHORITY_MISMATCH",
            )
            return None
        try:
            manifest_bytes = self._verified_reader_bytes(
                expected_manifest_relative,
                expected_manifest_sha256,
                max_bytes=len(expected_manifest_bytes),
            )
        except PathBoundaryViolation as error:
            self._append_release_issue(
                issues,
                expectations,
                missing=error.reason_code == "FILE_MISSING",
                reason_code=error.reason_code,
            )
            return None
        except (ArtifactIntegrityViolation, TypeError, ValueError):
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="GENERATION_MANIFEST_UNSAFE",
            )
            return None
        if len(manifest_bytes) != len(expected_manifest_bytes):
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="GENERATION_MANIFEST_SIZE_MISMATCH",
            )
            return None
        try:
            manifest = ProjectionGenerationManifest.model_validate_json(manifest_bytes)
        except ValidationError:
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="GENERATION_MANIFEST_INVALID",
            )
            return None
        if (
            canonical_bytes(manifest.model_dump(mode="json")) != manifest_bytes
            or manifest != expected_manifest
            or manifest_bytes != expected_manifest_bytes
        ):
            self._append_release_issue(
                issues,
                expectations,
                missing=False,
                reason_code="GENERATION_MANIFEST_AUTHORITY_MISMATCH",
            )
            return None

        generation_root = f"{run_id}/projections/generations/{manifest.generation_id}"
        manifest_name = pointer.manifest_relative_path.rsplit("/", maxsplit=1)[-1]
        root_expected = {"events.jsonl", "audit.jsonl", "cases", "packs", manifest_name}
        case_expected = {
            entry.relative_path.split("/", maxsplit=1)[1]
            for entry in manifest.entries
            if entry.kind == ProjectionArtifactKind.CASE_JSON
        }
        pack_expected = {
            entry.relative_path.split("/", maxsplit=1)[1]
            for entry in manifest.entries
            if entry.kind == ProjectionArtifactKind.PACK_JSON
        }
        inventories = tuple(
            _ProjectionInventoryExpectation(
                relative_directory=relative_directory,
                expected_names=frozenset(expected_names),
            )
            for relative_directory, expected_names in (
                (generation_root, root_expected),
                (f"{generation_root}/cases", case_expected),
                (f"{generation_root}/packs", pack_expected),
            )
        )
        inventory_failure = self._projection_inventory_failure(inventories)
        if inventory_failure is not None:
            inventory_reason, inventory_missing = inventory_failure
            self._append_release_issue(
                issues,
                expectations,
                missing=inventory_missing,
                reason_code=inventory_reason,
            )
            return None

        by_identity = {(item.kind, item.projection_id): item for item in expectations}
        return _ResolvedProjection(
            expectations=tuple(
                _ProjectionExpectation(
                    kind=entry.kind,
                    projection_id=entry.projection_id,
                    relative_path=f"{generation_root}/{entry.relative_path}",
                    expected_bytes=by_identity[(entry.kind, entry.projection_id)].expected_bytes,
                )
                for entry in expected_manifest.entries
            ),
            inventories=inventories,
            metadata_bytes=metadata_bytes,
        )

    def _projection_inventory_failure(
        self,
        inventories: tuple[_ProjectionInventoryExpectation, ...],
    ) -> tuple[str, bool] | None:
        for inventory in inventories:
            try:
                hints = self._reader.list_projection_directory(
                    inventory.relative_directory,
                    len(inventory.expected_names) + 1,
                    512,
                )
            except PathBoundaryViolation as error:
                return (
                    "GENERATION_INVENTORY_UNSAFE",
                    error.reason_code in {"DIRECTORY_MISSING", "FILE_MISSING"},
                )
            except (ArtifactIntegrityViolation, BudgetExceeded):
                return "GENERATION_INVENTORY_UNSAFE", False
            observed = {hint.name for hint in hints if hint.name is not None}
            if (
                any(hint.name is None for hint in hints)
                or len(hints) != len(observed)
                or observed != inventory.expected_names
            ):
                missing_only = bool(inventory.expected_names - observed) and not (
                    observed - inventory.expected_names
                )
                return "GENERATION_INVENTORY_MISMATCH", missing_only
        return None

    def _verified_reader_bytes(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> bytes:
        snapshot = self._reader.read_verified(
            relative_path,
            expected_sha256,
            max_bytes=max_bytes,
        )
        payload = snapshot.bytes
        if not isinstance(payload, bytes):
            raise TypeError
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if (
            not isinstance(snapshot.size_bytes, int)
            or isinstance(snapshot.size_bytes, bool)
            or snapshot.size_bytes != len(payload)
            or snapshot.sha256 != actual_sha256
            or (expected_sha256 is not None and actual_sha256 != expected_sha256)
        ):
            raise ValueError
        return payload

    @staticmethod
    def _append_release_issue(
        issues: list[ArtifactValidationIssue],
        expectations: tuple[_ProjectionExpectation, ...],
        *,
        missing: bool,
        reason_code: str,
    ) -> None:
        scope = next(
            (
                expected
                for expected in expectations
                if expected.kind == ProjectionArtifactKind.EVENTS_JSONL
            ),
            expectations[0],
        )
        issues.append(
            ArtifactValidationIssue(
                code=(
                    ArtifactValidationIssueCode.PROJECTION_MISSING
                    if missing
                    else ArtifactValidationIssueCode.PROJECTION_UNSAFE
                ),
                area=ArtifactValidationArea.PROJECTION,
                projection_kind=scope.kind,
                projection_id=scope.projection_id,
                reason_code=reason_code,
            )
        )

    def _report(
        self,
        run_id: str,
        head: AuditHead | None,
        counts: ArtifactValidationCounts,
        issues: list[ArtifactValidationIssue],
    ) -> ArtifactValidationReport:
        unique = {issue.sort_key: issue for issue in issues}
        ordered = tuple(unique[key] for key in sorted(unique))
        return ArtifactValidationReport(
            run_id=run_id,
            manifest_id=head.manifest_id if head is not None else None,
            audit_head_sequence=head.sequence if head is not None else None,
            audit_head_hash=head.entry_hash if head is not None else None,
            budget=self._budget,
            counts=counts,
            issues=ordered,
        )

    @staticmethod
    def _budget_issue(
        code: ArtifactValidationIssueCode,
        limit: int,
        observed: int,
    ) -> ArtifactValidationIssue:
        return ArtifactValidationIssue(
            code=code,
            area=ArtifactValidationArea.BUDGET,
            limit=limit,
            observed=observed,
        )


def artifact_budget_preflight_report(
    *,
    run_id: str,
    budget: ArtifactValidationBudget,
    counts: ArtifactValidationCounts,
) -> ArtifactValidationReport | None:
    """Return a typed early report before any potentially unbounded repository read."""

    run_id = require_reference_token(run_id, "artifact budget preflight run_id")
    if not isinstance(budget, ArtifactValidationBudget):
        raise TypeError("artifact budget preflight requires ArtifactValidationBudget")
    if not isinstance(counts, ArtifactValidationCounts):
        raise TypeError("artifact budget preflight requires ArtifactValidationCounts")
    checks = (
        (
            ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
            budget.max_document_bytes,
            counts.max_document_bytes,
        ),
        (
            ArtifactValidationIssueCode.AUDIT_BUDGET_EXCEEDED,
            budget.max_audit_entries,
            counts.audit_entries,
        ),
        (ArtifactValidationIssueCode.EVENT_BUDGET_EXCEEDED, budget.max_events, counts.events),
        (ArtifactValidationIssueCode.CASE_BUDGET_EXCEEDED, budget.max_cases, counts.cases),
        (ArtifactValidationIssueCode.PACK_BUDGET_EXCEEDED, budget.max_packs, counts.packs),
        (ArtifactValidationIssueCode.MEDIA_BUDGET_EXCEEDED, budget.max_media, counts.media),
    )
    issues = tuple(
        ArtifactValidationIssue(
            code=code,
            area=ArtifactValidationArea.BUDGET,
            limit=limit,
            observed=observed,
        )
        for code, limit, observed in checks
        if observed > limit
    )
    if not issues:
        return None
    return ArtifactValidationReport(
        run_id=run_id,
        budget=budget,
        counts=counts,
        issues=tuple(sorted(issues, key=lambda issue: issue.sort_key)),
    )


_M3_AREAS = {
    M3ArtifactInventoryKind.MODEL_CALL_CLAIM: M3ArtifactValidationArea.CLAIM,
    M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY: M3ArtifactValidationArea.CLAIM,
    M3ArtifactInventoryKind.MODEL_RESPONSE: M3ArtifactValidationArea.RESPONSE,
    M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT: M3ArtifactValidationArea.PARSE,
    M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT: M3ArtifactValidationArea.PARSE,
    M3ArtifactInventoryKind.MODEL_CACHE_ENTRY: M3ArtifactValidationArea.CACHE,
    M3ArtifactInventoryKind.MODEL_CALL_USAGE: M3ArtifactValidationArea.USAGE,
    M3ArtifactInventoryKind.SCREENING_RESULT: M3ArtifactValidationArea.SCREENING,
    M3ArtifactInventoryKind.VERDICT: M3ArtifactValidationArea.VERDICT,
    M3ArtifactInventoryKind.PROCEDURAL_REVIEW: M3ArtifactValidationArea.REVIEW,
    M3ArtifactInventoryKind.PROCEDURAL_DEFECT: M3ArtifactValidationArea.REVIEW,
    M3ArtifactInventoryKind.BACKLOG_ITEM: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_HEAD: M3ArtifactValidationArea.BACKLOG,
    M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT: M3ArtifactValidationArea.BACKLOG,
}
_M3_COUNT_FIELDS = {
    M3ArtifactInventoryKind.MODEL_CALL_CLAIM: "model_call_claims",
    M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY: "model_call_failure_authorities",
    M3ArtifactInventoryKind.MODEL_RESPONSE: "model_responses",
    M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT: "parsed_screening_outputs",
    M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT: "model_parse_receipts",
    M3ArtifactInventoryKind.MODEL_CACHE_ENTRY: "model_cache_entries",
    M3ArtifactInventoryKind.MODEL_CALL_USAGE: "model_call_usage",
    M3ArtifactInventoryKind.SCREENING_RESULT: "screening_results",
    M3ArtifactInventoryKind.VERDICT: "verdicts",
    M3ArtifactInventoryKind.PROCEDURAL_REVIEW: "procedural_reviews",
    M3ArtifactInventoryKind.PROCEDURAL_DEFECT: "procedural_defects",
    M3ArtifactInventoryKind.BACKLOG_ITEM: "backlog_items",
    M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION: "backlog_item_versions",
    M3ArtifactInventoryKind.BACKLOG_HEAD: "backlog_heads",
    M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT: ("backlog_completion_receipts"),
}

_RAW_RESPONSE_FILE_NAME = re.compile(r"^(?P<response_id>[0-9a-f]{64})\.json$")


@dataclass(frozen=True, slots=True)
class _PhysicalRawResponse:
    response_id: str
    relative_path: str
    source_token: str
    size_bytes: int
    identity_token: str

    @property
    def fingerprint(self) -> tuple[str, str, str, int, str]:
        return (
            self.response_id,
            self.relative_path,
            self.source_token,
            self.size_bytes,
            self.identity_token,
        )


@dataclass(frozen=True, slots=True)
class _PhysicalRawInventory:
    directory_found: bool
    bounded: bool
    entries_observed: int
    files: tuple[_PhysicalRawResponse, ...]
    issues: tuple[M3ArtifactValidationIssue, ...]

    @property
    def fingerprint(self) -> tuple[object, ...]:
        return (
            self.directory_found,
            self.bounded,
            self.entries_observed,
            tuple(file.fingerprint for file in self.files),
            tuple(issue.sort_key for issue in self.issues),
        )


class M3ArtifactValidator:
    """Validate all M3 roots plus physical raw-response bytes without mutation."""

    __slots__ = ("_authority", "_budget", "_counts", "_reader")

    def __init__(
        self,
        *,
        authority: M3ArtifactAuthorityReader,
        artifact_reader: M3ArtifactReader,
        authority_counts: M3ArtifactValidationCounts,
        budget: M3ArtifactValidationBudget | None = None,
    ) -> None:
        if not isinstance(authority_counts, M3ArtifactValidationCounts):
            raise TypeError("M3 authority_counts must be M3ArtifactValidationCounts")
        self._authority = authority
        self._reader = artifact_reader
        self._counts = authority_counts
        self._budget = budget or M3ArtifactValidationBudget()

    def validate(
        self,
        run_id: str,
        m2_report: ArtifactValidationReport,
    ) -> M3ArtifactValidationReport:
        run_id = require_reference_token(run_id, "M3 artifact validator run_id")
        if not isinstance(m2_report, ArtifactValidationReport):
            raise TypeError("M3 artifact validation requires an M2 validation report")
        if m2_report.run_id != run_id:
            raise ContractViolation("M3 and M2 artifact validation run IDs differ")
        preflight = m3_artifact_budget_preflight_report(
            run_id=run_id,
            m2_report=m2_report,
            budget=self._budget,
            counts=self._counts,
        )
        if preflight is not None:
            return preflight

        snapshot = self._authority.scan(run_id)
        issues = self._authority_issues(snapshot.failures)
        traversed = self._append_inventory_issues(snapshot.traversed, issues)
        physical = self._collect_physical_raw_inventory(run_id)
        issues.extend(physical.issues)
        reported_counts = M3ArtifactValidationCounts.model_validate(
            {
                **self._counts.model_dump(mode="python", exclude={"documents"}),
                "physical_raw_response_entries": physical.entries_observed,
                "physical_raw_response_files": len(physical.files),
                "physical_raw_response_bytes": sum(item.size_bytes for item in physical.files),
                "max_physical_raw_response_bytes": max(
                    (item.size_bytes for item in physical.files),
                    default=0,
                ),
            }
        )
        self._append_physical_budget_issues(reported_counts, physical, issues)
        self._append_unreferenced_raw_responses(
            physical,
            snapshot.raw_responses,
            snapshot.failures,
            issues,
        )
        physical_budget_failed = any(
            issue.code
            in {
                M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED,
                M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
                M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
            }
            for issue in issues
        )
        if physical.bounded and not physical_budget_failed:
            self._validate_raw_responses(
                run_id,
                snapshot.raw_responses,
                snapshot.failures,
                traversed[M3ArtifactInventoryKind.MODEL_RESPONSE],
                issues,
            )
            rescanned = self._collect_physical_raw_inventory(run_id)
            if rescanned.fingerprint != physical.fingerprint:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=recovery_source_token(f"{run_id}/model_responses"),
                        reason_code="DIRECTORY_CHANGED_DURING_VALIDATION",
                    )
                )
            issues.extend(rescanned.issues)
        unique = {issue.sort_key: issue for issue in issues}
        ordered = tuple(unique[key] for key in sorted(unique))
        return M3ArtifactValidationReport(
            run_id=run_id,
            m2_report=m2_report,
            budget=self._budget,
            counts=reported_counts,
            issues=ordered,
        )

    @staticmethod
    def _authority_issues(
        failures: tuple[M3AuthorityFailureObservation, ...],
    ) -> list[M3ArtifactValidationIssue]:
        issues: list[M3ArtifactValidationIssue] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        failure_codes = {
            "DOCUMENT_INVALID": M3ArtifactValidationIssueCode.AUTHORITY_DOCUMENT_INVALID,
            "INDEX_MISMATCH": M3ArtifactValidationIssueCode.AUTHORITY_INDEX_MISMATCH,
            "REFERENCE_INVALID": M3ArtifactValidationIssueCode.AUTHORITY_REFERENCE_INVALID,
        }
        for failure in failures:
            if not isinstance(failure.inventory_kind, M3ArtifactInventoryKind):
                raise ContractViolation("M3 authority reader returned an unknown inventory kind")
            code = failure_codes.get(str(failure.failure_type))
            if code is None:
                raise ContractViolation("M3 authority reader returned an unknown failure type")
            try:
                issue = M3ArtifactValidationIssue(
                    code=code,
                    area=_M3_AREAS[failure.inventory_kind],
                    inventory_kind=failure.inventory_kind,
                    record_identity_sha256=failure.record_identity_sha256,
                    artifact_id=failure.artifact_id,
                    reason_code=failure.reason_code,
                )
            except (TypeError, ValueError):
                raise ContractViolation(
                    "M3 authority reader returned invalid failure context"
                ) from None
            key = (
                str(failure.failure_type),
                failure.inventory_kind.value,
                issue.record_identity_sha256 or "",
                issue.artifact_id or "",
                issue.reason_code or "",
            )
            if key in seen:
                raise ContractViolation(
                    "M3 authority reader returned a duplicate failure observation"
                )
            seen.add(key)
            issues.append(issue)
        return issues

    def _append_inventory_issues(
        self,
        traversed: tuple[M3TraversedObservation, ...],
        issues: list[M3ArtifactValidationIssue],
    ) -> dict[M3ArtifactInventoryKind, int]:
        observed: dict[M3ArtifactInventoryKind, int] = {}
        for item in traversed:
            if (
                not isinstance(item.inventory_kind, M3ArtifactInventoryKind)
                or not isinstance(item.count, int)
                or isinstance(item.count, bool)
                or item.count < 0
                or item.inventory_kind in observed
            ):
                raise ContractViolation("M3 authority reader returned invalid inventory counts")
            observed[item.inventory_kind] = item.count
        if set(observed) != set(M3ArtifactInventoryKind):
            raise ContractViolation("M3 authority reader omitted an inventory count")
        for kind in M3ArtifactInventoryKind:
            authoritative = int(getattr(self._counts, _M3_COUNT_FIELDS[kind]))
            if authoritative == observed[kind]:
                continue
            issues.append(
                M3ArtifactValidationIssue(
                    code=M3ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH,
                    area=_M3_AREAS[kind],
                    inventory_kind=kind,
                    authoritative_count=authoritative,
                    traversed_count=observed[kind],
                )
            )
        return observed

    def _collect_physical_raw_inventory(self, run_id: str) -> _PhysicalRawInventory:
        directory = f"{run_id}/model_responses"
        try:
            hints = self._reader.list_model_response_recovery_directory(
                directory,
                self._budget.max_raw_response_files,
                self._budget.max_raw_response_name_bytes,
            )
        except BudgetExceeded:
            return _PhysicalRawInventory(
                directory_found=True,
                bounded=False,
                entries_observed=self._budget.max_raw_response_files + 1,
                files=(),
                issues=(
                    M3ArtifactValidationIssue(
                        code=(
                            M3ArtifactValidationIssueCode.RAW_RESPONSE_FILE_COUNT_BUDGET_EXCEEDED
                        ),
                        area=M3ArtifactValidationArea.BUDGET,
                        limit=self._budget.max_raw_response_files,
                        observed=self._budget.max_raw_response_files + 1,
                    ),
                ),
            )
        except PathBoundaryViolation as error:
            if error.reason_code == "DIRECTORY_MISSING":
                return _PhysicalRawInventory(
                    directory_found=False,
                    bounded=True,
                    entries_observed=0,
                    files=(),
                    issues=(),
                )
            return _PhysicalRawInventory(
                directory_found=False,
                bounded=True,
                entries_observed=0,
                files=(),
                issues=(
                    self._inventory_unsafe_issue(
                        source_token=recovery_source_token(directory),
                        reason_code=error.reason_code,
                    ),
                ),
            )
        except (TypeError, ValueError):
            return _PhysicalRawInventory(
                directory_found=False,
                bounded=True,
                entries_observed=0,
                files=(),
                issues=(
                    self._inventory_unsafe_issue(
                        source_token=recovery_source_token(directory),
                        reason_code="INVENTORY_READER_REJECTED",
                    ),
                ),
            )

        files: list[_PhysicalRawResponse] = []
        issues: list[M3ArtifactValidationIssue] = []
        seen_sources: set[str] = set()
        for hint in hints:
            try:
                source_token = str(hint.source_token)
                if source_token in seen_sources:
                    raise ValueError
                seen_sources.add(source_token)
                name = hint.name
                reason_code = hint.reason_code
            except (AttributeError, TypeError, ValueError):
                raise ContractViolation(
                    "M3 artifact reader returned invalid physical inventory hints"
                ) from None
            if name is None:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        reason_code=reason_code or "INVALID_ENTRY_NAME",
                    )
                )
                continue
            matched = _RAW_RESPONSE_FILE_NAME.fullmatch(name)
            if matched is None or reason_code is not None:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        reason_code=reason_code or "INVALID_ENTRY_NAME",
                    )
                )
                continue
            response_id = matched.group("response_id")
            relative_path = f"{directory}/{name}"
            try:
                metadata = self._reader.inspect_verified(relative_path)
                if (
                    metadata.relative_path != relative_path
                    or not isinstance(metadata.size_bytes, int)
                    or isinstance(metadata.size_bytes, bool)
                    or metadata.size_bytes < 0
                    or not isinstance(metadata.identity_token, str)
                    or re.fullmatch(r"[0-9a-f]{64}", metadata.identity_token) is None
                ):
                    raise ValueError
            except BudgetExceeded:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        artifact_id=response_id,
                        reason_code="INVENTORY_METADATA_BUDGET_EXCEEDED",
                    )
                )
                continue
            except PathBoundaryViolation as error:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        artifact_id=response_id,
                        reason_code=error.reason_code,
                    )
                )
                continue
            except ArtifactIntegrityViolation:
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        artifact_id=response_id,
                        reason_code="ARTIFACT_INTEGRITY_FAILURE",
                    )
                )
                continue
            except (AttributeError, TypeError, ValueError):
                issues.append(
                    self._inventory_unsafe_issue(
                        source_token=source_token,
                        artifact_id=response_id,
                        reason_code="INVENTORY_METADATA_INVALID",
                    )
                )
                continue
            files.append(
                _PhysicalRawResponse(
                    response_id=response_id,
                    relative_path=relative_path,
                    source_token=source_token,
                    size_bytes=metadata.size_bytes,
                    identity_token=metadata.identity_token,
                )
            )
        files.sort(key=lambda item: (item.response_id, item.source_token))
        if len({item.response_id for item in files}) != len(files):
            raise ContractViolation("physical raw-response inventory contains duplicate IDs")
        return _PhysicalRawInventory(
            directory_found=True,
            bounded=True,
            entries_observed=len(hints),
            files=tuple(files),
            issues=tuple(sorted(issues, key=lambda issue: issue.sort_key)),
        )

    def _append_physical_budget_issues(
        self,
        counts: M3ArtifactValidationCounts,
        physical: _PhysicalRawInventory,
        issues: list[M3ArtifactValidationIssue],
    ) -> None:
        if not physical.bounded:
            return
        checks = (
            (
                M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
                self._budget.max_raw_response_bytes,
                counts.max_physical_raw_response_bytes,
            ),
            (
                M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
                self._budget.max_raw_response_total_bytes,
                counts.physical_raw_response_bytes,
            ),
        )
        for code, limit, observed in checks:
            if observed > limit:
                issues.append(
                    M3ArtifactValidationIssue(
                        code=code,
                        area=M3ArtifactValidationArea.BUDGET,
                        limit=limit,
                        observed=observed,
                    )
                )

    @staticmethod
    def _append_unreferenced_raw_responses(
        physical: _PhysicalRawInventory,
        observations: tuple[M3RawResponseObservation, ...],
        failures: tuple[M3AuthorityFailureObservation, ...],
        issues: list[M3ArtifactValidationIssue],
    ) -> None:
        referenced_ids = {observation.response.response_id for observation in observations}
        referenced_ids.update(
            failure.artifact_id
            for failure in failures
            if failure.inventory_kind == M3ArtifactInventoryKind.MODEL_RESPONSE
            and failure.artifact_id is not None
        )
        for item in physical.files:
            if item.response_id in referenced_ids:
                continue
            issues.append(
                M3ArtifactValidationIssue(
                    code=M3ArtifactValidationIssueCode.RAW_RESPONSE_UNREFERENCED,
                    area=M3ArtifactValidationArea.RAW_RESPONSE,
                    artifact_id=item.response_id,
                    source_token=item.source_token,
                )
            )

    @staticmethod
    def _inventory_unsafe_issue(
        *,
        source_token: str,
        reason_code: str,
        artifact_id: str | None = None,
    ) -> M3ArtifactValidationIssue:
        return M3ArtifactValidationIssue(
            code=M3ArtifactValidationIssueCode.RAW_RESPONSE_INVENTORY_UNSAFE,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            artifact_id=artifact_id,
            source_token=source_token,
            reason_code=reason_code,
        )

    def _validate_raw_responses(
        self,
        run_id: str,
        observations: tuple[M3RawResponseObservation, ...],
        failures: tuple[M3AuthorityFailureObservation, ...],
        traversed_response_count: int,
        issues: list[M3ArtifactValidationIssue],
    ) -> None:
        seen_response_ids: set[str] = set()
        seen_record_identities: set[str] = set()
        invalid_record_identities = {
            failure.record_identity_sha256
            for failure in failures
            if failure.inventory_kind == M3ArtifactInventoryKind.MODEL_RESPONSE
            and str(failure.failure_type) in {"DOCUMENT_INVALID", "INDEX_MISMATCH"}
        }
        remaining_raw_bytes = self._budget.max_raw_response_total_bytes
        for observation in observations:
            response = observation.response
            if not isinstance(response, VLMResponse):
                raise ContractViolation("M3 authority reader returned a non-response root")
            if (
                response.response_id in seen_response_ids
                or observation.record_identity_sha256 in seen_record_identities
                or observation.record_identity_sha256 in invalid_record_identities
            ):
                raise ContractViolation("M3 authority reader returned a duplicate response root")
            seen_response_ids.add(response.response_id)
            seen_record_identities.add(observation.record_identity_sha256)
            expected_path = f"{run_id}/model_responses/{response.response_id}.json"
            if response.run_id != run_id or response.raw_response_ref != expected_path:
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
                        reason_code="RAW_RESPONSE_LOCATOR_SCOPE_MISMATCH",
                    )
                )
                continue
            try:
                read_limit = min(response.size_bytes, remaining_raw_bytes)
                snapshot = self._reader.read_verified(
                    response.raw_response_ref,
                    response.content_sha256,
                    max_bytes=read_limit,
                )
            except BudgetExceeded:
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
                        reason_code="READER_BUDGET_EXCEEDED",
                    )
                )
                continue
            except PathBoundaryViolation as error:
                code = (
                    M3ArtifactValidationIssueCode.RAW_RESPONSE_MISSING
                    if error.reason_code == "FILE_MISSING"
                    else M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE
                )
                issues.append(self._raw_issue(observation, code, reason_code=error.reason_code))
                continue
            except ArtifactIntegrityViolation:
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
                        reason_code="ARTIFACT_INTEGRITY_FAILURE",
                    )
                )
                continue
            except (TypeError, ValueError):
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
                        reason_code="READER_LIMIT_REJECTED",
                    )
                )
                continue
            try:
                actual_bytes = snapshot.bytes
                if not isinstance(actual_bytes, bytes):
                    raise TypeError
                actual_size = len(actual_bytes)
                actual_sha256 = hashlib.sha256(actual_bytes).hexdigest()
                if (
                    not isinstance(snapshot.size_bytes, int)
                    or isinstance(snapshot.size_bytes, bool)
                    or snapshot.size_bytes != actual_size
                    or snapshot.sha256 != actual_sha256
                ):
                    raise ValueError
            except (AttributeError, TypeError, ValueError):
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE,
                        reason_code="READER_RECEIPT_MISMATCH",
                    )
                )
                continue
            remaining_raw_bytes -= actual_size
            if actual_sha256 != response.content_sha256 or actual_size != response.size_bytes:
                issues.append(
                    self._raw_issue(
                        observation,
                        M3ArtifactValidationIssueCode.RAW_RESPONSE_CONTENT_MISMATCH,
                        expected_sha256=response.content_sha256,
                        actual_sha256=actual_sha256,
                        expected_size_bytes=response.size_bytes,
                        actual_size_bytes=actual_size,
                    )
                )

        if len(seen_record_identities | invalid_record_identities) != (traversed_response_count):
            raise ContractViolation(
                "M3 authority reader did not account for every traversed response row"
            )

    @staticmethod
    def _raw_issue(
        observation: M3RawResponseObservation,
        code: M3ArtifactValidationIssueCode,
        *,
        reason_code: str | None = None,
        expected_sha256: str | None = None,
        actual_sha256: str | None = None,
        expected_size_bytes: int | None = None,
        actual_size_bytes: int | None = None,
    ) -> M3ArtifactValidationIssue:
        return M3ArtifactValidationIssue(
            code=code,
            area=M3ArtifactValidationArea.RAW_RESPONSE,
            inventory_kind=M3ArtifactInventoryKind.MODEL_RESPONSE,
            record_identity_sha256=observation.record_identity_sha256,
            artifact_id=observation.response.response_id,
            reason_code=reason_code,
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
            expected_size_bytes=expected_size_bytes,
            actual_size_bytes=actual_size_bytes,
        )


def m3_artifact_budget_preflight_report(
    *,
    run_id: str,
    m2_report: ArtifactValidationReport,
    budget: M3ArtifactValidationBudget,
    counts: M3ArtifactValidationCounts,
) -> M3ArtifactValidationReport | None:
    """Stop before row materialization or raw-file reads when M3 limits are exceeded."""

    run_id = require_reference_token(run_id, "M3 artifact budget preflight run_id")
    if not isinstance(m2_report, ArtifactValidationReport) or m2_report.run_id != run_id:
        raise TypeError("M3 artifact preflight requires the same-run M2 report")
    if not isinstance(budget, M3ArtifactValidationBudget):
        raise TypeError("M3 artifact preflight requires M3ArtifactValidationBudget")
    if not isinstance(counts, M3ArtifactValidationCounts):
        raise TypeError("M3 artifact preflight requires M3ArtifactValidationCounts")
    checks = (
        (
            M3ArtifactValidationIssueCode.DOCUMENT_COUNT_BUDGET_EXCEEDED,
            budget.max_documents,
            counts.documents,
        ),
        (
            M3ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
            budget.max_document_bytes,
            counts.max_document_bytes,
        ),
        (
            M3ArtifactValidationIssueCode.RAW_RESPONSE_BYTES_BUDGET_EXCEEDED,
            budget.max_raw_response_bytes,
            counts.max_raw_response_bytes,
        ),
        (
            M3ArtifactValidationIssueCode.RAW_RESPONSE_TOTAL_BYTES_BUDGET_EXCEEDED,
            budget.max_raw_response_total_bytes,
            counts.raw_response_bytes,
        ),
    )
    issues = tuple(
        M3ArtifactValidationIssue(
            code=code,
            area=M3ArtifactValidationArea.BUDGET,
            limit=limit,
            observed=observed,
        )
        for code, limit, observed in checks
        if observed > limit
    )
    if not issues:
        return None
    return M3ArtifactValidationReport(
        run_id=run_id,
        m2_report=m2_report,
        budget=budget,
        counts=counts,
        issues=tuple(sorted(issues, key=lambda issue: issue.sort_key)),
    )


__all__ = [
    "ArtifactReader",
    "ArtifactSnapshot",
    "ArtifactValidator",
    "M3ArtifactAuthorityReader",
    "M3ArtifactReader",
    "M3ArtifactValidator",
    "artifact_budget_preflight_report",
    "m3_artifact_budget_preflight_report",
]
