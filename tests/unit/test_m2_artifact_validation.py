from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import cast

from labcourt.application.artifact_validation import (
    ArtifactReader,
    ArtifactValidator,
    artifact_budget_preflight_report,
)
from labcourt.contracts.artifact_validation import (
    ArtifactInventoryKind,
    ArtifactValidationBudget,
    ArtifactValidationCounts,
    ArtifactValidationIssueCode,
    ProjectionArtifactKind,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.projection_generation import (
    ProjectionCurrentPointer,
    ProjectionGenerationEntry,
    ProjectionGenerationManifest,
)
from labcourt.exceptions import PathBoundaryViolation
from labcourt.ports.evidence_repository import AuditHead, EvidenceRepository

RUN_ID = "artifact-validator-unit"
MANIFEST_ID = "1" * 64
ZERO_SHA256 = "0" * 64


class _EmptyRepository:
    def get_audit_head(self, run_id: str) -> AuditHead:
        return AuditHead(
            run_id=run_id,
            manifest_id=MANIFEST_ID,
            run_revision=0,
            sequence=-1,
            entry_hash=ZERO_SHA256,
        )

    def list_audit_entries(self, run_id: str) -> tuple[object, ...]:
        del run_id
        return ()

    def list_events(self, run_id: str) -> tuple[object, ...]:
        del run_id
        return ()


@dataclass(frozen=True, slots=True)
class _ForgedSnapshot:
    bytes: bytes = b""
    size_bytes: int = 0
    sha256: str = "f" * 64


class _ForgedReader:
    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> _ForgedSnapshot:
        del relative_path, expected_sha256, max_bytes
        return _ForgedSnapshot()


@dataclass(frozen=True, slots=True)
class _VerifiedSnapshot:
    bytes: bytes = b""
    size_bytes: int = 0
    sha256: str = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class _Hint:
    name: str | None
    source_token: str = "1" * 64
    reason_code: str | None = None


class _VerifiedReader:
    def __init__(self) -> None:
        self.reads: list[tuple[str, str | None, int | None]] = []
        entries = tuple(
            sorted(
                (
                    ProjectionGenerationEntry(
                        kind=kind,
                        projection_id=RUN_ID,
                        relative_path=relative_path,
                        sha256=hashlib.sha256(b"").hexdigest(),
                        size_bytes=0,
                    )
                    for kind, relative_path in (
                        (ProjectionArtifactKind.EVENTS_JSONL, "events.jsonl"),
                        (ProjectionArtifactKind.AUDIT_JSONL, "audit.jsonl"),
                    )
                ),
                key=lambda entry: entry.sort_key,
            )
        )
        manifest = ProjectionGenerationManifest(
            run_id=RUN_ID,
            audit_head_sequence=-1,
            audit_head_hash=ZERO_SHA256,
            entries=entries,
        )
        manifest_bytes = canonical_bytes(manifest.model_dump(mode="json"))
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        self.generation_root = f"{RUN_ID}/projections/generations/{manifest.generation_id}"
        self.manifest_name = f"manifest-{manifest_sha}.json"
        manifest_path = f"{self.generation_root}/{self.manifest_name}"
        pointer = ProjectionCurrentPointer(
            run_id=RUN_ID,
            audit_head_sequence=-1,
            audit_head_hash=ZERO_SHA256,
            generation_id=manifest.generation_id,
            manifest_relative_path=manifest_path,
            manifest_sha256=manifest_sha,
            manifest_size_bytes=len(manifest_bytes),
        )
        self.documents = {
            f"{RUN_ID}/projections/current.json": canonical_bytes(pointer.model_dump(mode="json")),
            manifest_path: manifest_bytes,
            f"{self.generation_root}/events.jsonl": b"",
            f"{self.generation_root}/audit.jsonl": b"",
        }

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> _VerifiedSnapshot:
        self.reads.append((relative_path, expected_sha256, max_bytes))
        payload = self.documents[relative_path]
        if max_bytes is not None and len(payload) > max_bytes:
            raise PathBoundaryViolation("FILE_TOO_LARGE", relative_path)
        digest = hashlib.sha256(payload).hexdigest()
        assert expected_sha256 is None or digest == expected_sha256
        return _VerifiedSnapshot(bytes=payload, size_bytes=len(payload), sha256=digest)

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[_Hint, ...]:
        del max_items, max_name_bytes
        names: tuple[str, ...]
        if relative_path == self.generation_root:
            names = ("audit.jsonl", "cases", "events.jsonl", self.manifest_name, "packs")
        else:
            names = ()
        return tuple(_Hint(name) for name in names)


class _IncompleteInventoryReader(_VerifiedReader):
    """Expose a split view: direct reads work while the directory omits a member."""

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[_Hint, ...]:
        hints = super().list_projection_directory(relative_path, max_items, max_name_bytes)
        if relative_path != self.generation_root:
            return hints
        return tuple(hint for hint in hints if hint.name != "events.jsonl")


class _LateExtraInventoryReader(_VerifiedReader):
    """Add a generation member after the validator's first exact inventory."""

    def __init__(self) -> None:
        super().__init__()
        self.added_late_member = False

    def read_verified(
        self,
        relative_path: str,
        expected_sha256: str | None = None,
        *,
        max_bytes: int | None = None,
    ) -> _VerifiedSnapshot:
        snapshot = super().read_verified(
            relative_path,
            expected_sha256,
            max_bytes=max_bytes,
        )
        if relative_path == f"{self.generation_root}/events.jsonl":
            self.added_late_member = True
        return snapshot

    def list_projection_directory(
        self,
        relative_path: str,
        max_items: int,
        max_name_bytes: int,
    ) -> tuple[_Hint, ...]:
        hints = super().list_projection_directory(relative_path, max_items, max_name_bytes)
        if relative_path == self.generation_root and self.added_late_member:
            return (*hints, _Hint("late-extra.json"))
        return hints


def test_artifact_validator_recomputes_projection_reader_receipts() -> None:
    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, _ForgedReader()),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert report.passed is False
    assert report.counts.projections == 0
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.PROJECTION_UNSAFE
    }
    assert {issue.reason_code for issue in report.issues} == {"CURRENT_POINTER_UNSAFE"}


def test_artifact_validator_rejects_generation_inventory_missing_a_readable_member() -> None:
    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, _IncompleteInventoryReader()),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert report.passed is False
    assert report.counts.projections == 0
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.PROJECTION_MISSING
    }
    assert {issue.reason_code for issue in report.issues} == {"GENERATION_INVENTORY_MISMATCH"}


def test_artifact_validator_rescans_generation_inventory_after_member_reads() -> None:
    reader = _LateExtraInventoryReader()

    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, reader),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert reader.added_late_member is True
    assert report.passed is False
    assert report.counts.projections == 0
    assert {issue.reason_code for issue in report.issues} == {"GENERATION_INVENTORY_MISMATCH"}


def test_artifact_validator_caps_current_pointer_before_parsing() -> None:
    reader = _VerifiedReader()
    current_path = f"{RUN_ID}/projections/current.json"
    reader.documents[current_path] = b"x" * (4 * 1024 + 1)

    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, reader),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert report.passed is False
    assert {issue.reason_code for issue in report.issues} == {"FILE_TOO_LARGE"}
    assert reader.reads == [(current_path, None, 4 * 1024)]


def test_artifact_validator_never_follows_a_non_authoritative_manifest_pointer() -> None:
    reader = _VerifiedReader()
    current_path = f"{RUN_ID}/projections/current.json"
    forged_generation = "e" * 64
    forged_manifest_sha256 = "f" * 64
    forged = ProjectionCurrentPointer(
        run_id=RUN_ID,
        audit_head_sequence=-1,
        audit_head_hash=ZERO_SHA256,
        generation_id=forged_generation,
        manifest_relative_path=(
            f"{RUN_ID}/projections/generations/{forged_generation}/"
            f"manifest-{forged_manifest_sha256}.json"
        ),
        manifest_sha256=forged_manifest_sha256,
        manifest_size_bytes=1_000_000_000,
    )
    reader.documents[current_path] = canonical_bytes(forged.model_dump(mode="json"))

    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, reader),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert report.passed is False
    assert {issue.reason_code for issue in report.issues} == {"CURRENT_POINTER_AUTHORITY_MISMATCH"}
    assert reader.reads == [(current_path, None, 4 * 1024)]


def test_artifact_validator_caps_every_current_release_read_from_authority() -> None:
    reader = _VerifiedReader()

    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, reader),
        authority_counts=ArtifactValidationCounts(),
    ).validate(RUN_ID)

    assert report.passed is True
    current_path = f"{RUN_ID}/projections/current.json"
    manifest_path = next(path for path in reader.documents if "/manifest-" in path)
    reads = {
        path: (expected_sha256, max_bytes) for path, expected_sha256, max_bytes in reader.reads
    }
    assert reads[current_path] == (None, 4 * 1024)
    assert reads[manifest_path] == (
        hashlib.sha256(reader.documents[manifest_path]).hexdigest(),
        len(reader.documents[manifest_path]),
    )
    for path in (
        f"{reader.generation_root}/events.jsonl",
        f"{reader.generation_root}/audit.jsonl",
    ):
        assert reads[path] == (None, len(reader.documents[path]))
    assert report.counts.projection_bytes == sum(
        len(payload) for payload in reader.documents.values()
    )


def test_complete_projection_release_budget_fails_before_any_filesystem_read() -> None:
    reader = _VerifiedReader()

    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, reader),
        authority_counts=ArtifactValidationCounts(),
        budget=ArtifactValidationBudget(max_projection_bytes=1),
    ).validate(RUN_ID)

    assert report.passed is False
    assert reader.reads == []
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.PROJECTION_BYTES_BUDGET_EXCEEDED
    }
    assert report.issues[0].limit == 1
    assert report.issues[0].observed is not None
    assert report.issues[0].observed > 1


def test_artifact_validator_reconciles_all_authority_inventory_counts() -> None:
    report = ArtifactValidator(
        repository=cast(EvidenceRepository, _EmptyRepository()),
        artifact_reader=cast(ArtifactReader, _VerifiedReader()),
        authority_counts=ArtifactValidationCounts(
            audit_entries=1,
            events=1,
            cases=1,
            packs=1,
            media=1,
        ),
    ).validate(RUN_ID)

    assert report.counts.audit_entries == 1
    assert report.counts.events == 1
    assert report.counts.cases == 1
    assert report.counts.packs == 1
    assert report.counts.media == 1
    assert report.counts.projections == 2
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.AUTHORITY_INVENTORY_MISMATCH
    }
    assert {issue.inventory_kind for issue in report.issues} == set(ArtifactInventoryKind)
    assert all(issue.authoritative_count == 1 for issue in report.issues)
    assert all(issue.traversed_count == 0 for issue in report.issues)


def test_artifact_budget_preflight_reports_all_excesses_in_stable_order() -> None:
    budget = ArtifactValidationBudget(
        max_audit_entries=2,
        max_document_bytes=2,
        max_events=2,
        max_cases=2,
        max_packs=2,
        max_media=2,
        max_projection_bytes=2,
    )
    report = artifact_budget_preflight_report(
        run_id=RUN_ID,
        budget=budget,
        counts=ArtifactValidationCounts(
            max_document_bytes=3,
            audit_entries=3,
            events=3,
            cases=3,
            packs=3,
            media=3,
        ),
    )

    assert report is not None
    assert report.passed is False
    assert {issue.code for issue in report.issues} == {
        ArtifactValidationIssueCode.AUDIT_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.CASE_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.EVENT_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.MEDIA_BUDGET_EXCEEDED,
        ArtifactValidationIssueCode.PACK_BUDGET_EXCEEDED,
    }
    assert tuple(issue.sort_key for issue in report.issues) == tuple(
        sorted(issue.sort_key for issue in report.issues)
    )
