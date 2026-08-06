"""Typed observations accepted by the M6 regression source-cut builder."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.cases import Case
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.m6_source_authority_store import M6SourceAuthoritySeal
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token


def _require_sha256(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class M6RegressionRequiredSource:
    """One Case revision enumerated from the authoritative evaluator scope."""

    source_run_id: str
    source_case_id: str
    source_case_revision: int
    source_case_document_sha256: str
    source_manifest_id: str

    def __post_init__(self) -> None:
        require_reference_token(self.source_run_id, "M6 required source run_id")
        require_reference_token(self.source_case_id, "M6 required source case_id")
        if (
            not isinstance(self.source_case_revision, int)
            or isinstance(self.source_case_revision, bool)
            or self.source_case_revision <= 0
        ):
            raise ValueError("M6 required source revision must be positive")
        _require_sha256(self.source_case_document_sha256, "M6 required Case document")
        _require_sha256(self.source_manifest_id, "M6 required source manifest")

    @property
    def sort_key(self) -> tuple[str, int]:
        return self.source_case_id, self.source_case_revision

    @property
    def source_key(self) -> tuple[str, str, int, str]:
        return (
            self.source_run_id,
            self.source_case_id,
            self.source_case_revision,
            self.source_case_document_sha256,
        )


@dataclass(frozen=True, slots=True)
class M6RegressionRunScopeObservation:
    """Complete required source scope observed from one private SQLite snapshot."""

    source_identity_sha256: str
    source_run_id: str
    audit_head_sequence: int
    audit_head_hash: str
    m5_validation_report: M5ArtifactValidationReport
    m5_validation_report_document: str
    required_sources: tuple[M6RegressionRequiredSource, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.source_identity_sha256, "M6 source snapshot identity")
        require_reference_token(self.source_run_id, "M6 source scope run_id")
        if (
            not isinstance(self.audit_head_sequence, int)
            or isinstance(self.audit_head_sequence, bool)
            or self.audit_head_sequence < -1
        ):
            raise ValueError("M6 source scope audit sequence must be at least -1")
        _require_sha256(self.audit_head_hash, "M6 source scope audit head")
        if not isinstance(self.m5_validation_report, M5ArtifactValidationReport):
            raise TypeError("M6 source scope requires a typed M5 validation report")
        if not isinstance(self.m5_validation_report_document, str):
            raise TypeError("M6 source scope report document must be text")
        if not isinstance(self.required_sources, tuple) or not self.required_sources:
            raise ValueError("M6 source scope requires at least one source Case")
        if any(not isinstance(item, M6RegressionRequiredSource) for item in self.required_sources):
            raise TypeError("M6 source scope requires typed source items")
        keys = tuple(item.sort_key for item in self.required_sources)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M6 required sources must be unique and ordered")
        if any(item.source_run_id != self.source_run_id for item in self.required_sources):
            raise ValueError("M6 required source belongs to another run")


@dataclass(frozen=True, slots=True)
class M6RegressionSealedSourceObservation:
    """One source-store bundle after immutable readback verification."""

    replay_input_closure: M6ReplayInputClosureAuthority
    replay_input_authority: M6ReplayInputAuthority
    source_validation_report: M5ArtifactValidationReport
    source_case: Case
    source_manifest: RunManifest
    source_seal: M6SourceAuthoritySeal
    replay_input_closure_document: str
    replay_input_authority_document: str
    source_validation_report_document: str
    source_case_document: str
    source_manifest_document: str
    source_seal_document: str

    def __post_init__(self) -> None:
        typed = (
            (self.replay_input_closure, M6ReplayInputClosureAuthority),
            (self.replay_input_authority, M6ReplayInputAuthority),
            (self.source_validation_report, M5ArtifactValidationReport),
            (self.source_case, Case),
            (self.source_manifest, RunManifest),
            (self.source_seal, M6SourceAuthoritySeal),
        )
        if any(not isinstance(value, expected) for value, expected in typed):
            raise TypeError("M6 sealed source observation requires typed documents")
        documents = (
            self.replay_input_closure_document,
            self.replay_input_authority_document,
            self.source_validation_report_document,
            self.source_case_document,
            self.source_manifest_document,
            self.source_seal_document,
        )
        if any(not isinstance(value, str) or not value for value in documents):
            raise ValueError("M6 sealed source observation requires non-empty documents")

    @property
    def source_key(self) -> tuple[str, str, int, str]:
        closure = self.replay_input_closure
        if (
            closure.source_case_id is None
            or closure.source_case_revision is None
            or closure.source_case_document_sha256 is None
        ):
            raise ValueError("M6 sealed regression source requires a source Case")
        return (
            closure.source_run_id,
            closure.source_case_id,
            closure.source_case_revision,
            closure.source_case_document_sha256,
        )


__all__ = [
    "M6RegressionRequiredSource",
    "M6RegressionRunScopeObservation",
    "M6RegressionSealedSourceObservation",
]
