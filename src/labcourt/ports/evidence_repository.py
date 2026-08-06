"""Run-scoped persistence and physical-evidence verification ports for M2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import EvidenceFailureCode
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import Crop, EvidencePack, EvidencePackDraft
from labcourt.contracts.frames import FrameRef, Sha256Hex
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport


@dataclass(frozen=True, slots=True)
class AuditHead:
    """The authoritative audit and optimistic-write head for one run."""

    run_id: str
    manifest_id: Sha256Hex
    run_revision: int
    sequence: int
    entry_hash: Sha256Hex


@dataclass(frozen=True, slots=True)
class CaseSnapshot:
    """A validated Case paired with its repository revision."""

    case: Case
    revision: int


@dataclass(frozen=True, slots=True)
class PublishResult:
    """Result of a new publication or an idempotent pack retry."""

    case: CaseSnapshot
    pack: EvidencePack
    created: bool


class EvidenceVerifier(Protocol):
    """Trusted adapter boundary for facts the SQLite repository cannot observe."""

    def verify_crop(self, crop: Crop) -> ArtifactVerification: ...

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool: ...


class EvidenceRepository(Protocol):
    """Authoritative, explicitly run-scoped evidence persistence boundary."""

    def register_run(self, run_id: str, manifest: RunManifest) -> None: ...

    def register_frame(self, run_id: str, frame: FrameRef) -> None: ...

    def register_detection(self, run_id: str, detection: Detection) -> None: ...

    def load_run_manifest(self, run_id: str) -> RunManifest: ...

    def create_or_get_case(self, run_id: str, event: CandidateEvent) -> CaseSnapshot: ...

    def publish_pack(
        self,
        run_id: str,
        expected_revision: int,
        pack: EvidencePackDraft,
    ) -> PublishResult: ...

    def record_evidence_failure(
        self,
        run_id: str,
        expected_revision: int,
        case_id: str,
        failure_code: EvidenceFailureCode,
    ) -> CaseSnapshot: ...

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot: ...

    def load_pack(self, run_id: str, pack_id: str) -> EvidencePack: ...

    def load_frame(self, run_id: str, frame_id: str) -> FrameRef: ...

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport: ...

    def list_events(self, run_id: str) -> tuple[CandidateEvent, ...]: ...

    def list_audit_entries(self, run_id: str) -> tuple[AuditEntry, ...]: ...

    def get_audit_head(self, run_id: str) -> AuditHead: ...


__all__ = [
    "AuditHead",
    "CaseSnapshot",
    "EvidenceRepository",
    "EvidenceVerifier",
    "PublishResult",
]
