"""Repository and filesystem boundaries for crash-safe media retention."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, Self

from pydantic import Field, field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import ArtifactKind, PurgeRecoveryKind
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef, PurgeItemResult, RetentionHold


class PurgeLease(FrozenContractModel):
    """Repository-authorized transition of one media object into private trash."""

    run_id: ReferenceToken
    media_sha256: Sha256Hex
    source_relative_path: str
    trash_relative_path: str
    crop_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    intent_audit_sequence: int = Field(ge=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "purge lease run_id")

    @field_validator("source_relative_path", "trash_relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_scope_and_stable_references(self) -> Self:
        expected_source = f"{self.run_id}/frames/{self.media_sha256}.png"
        expected_trash = f".trash/{self.run_id}/{self.media_sha256}.png"
        if self.source_relative_path != expected_source:
            raise ValueError("purge source path must use the canonical run media locator")
        if self.trash_relative_path != expected_trash:
            raise ValueError("purge trash path must use the canonical run trash locator")
        if any(ref.kind != ArtifactKind.CROP for ref in self.crop_refs):
            raise ValueError("purge lease crop_refs must identify crops")
        crop_keys = tuple(ref.sort_key for ref in self.crop_refs)
        if len(crop_keys) != len(set(crop_keys)):
            raise ValueError("purge lease crop_refs must be unique")
        if crop_keys != tuple(sorted(crop_keys)):
            raise ValueError("purge lease crop_refs must use stable order")
        return self


class PurgeRecoveryCandidate(FrozenContractModel):
    """One persisted recovery phase claimed by the run-scoped scheduler."""

    kind: PurgeRecoveryKind
    lease: PurgeLease
    completion_audit_sequence: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def validate_phase_audits(self) -> Self:
        if self.kind == PurgeRecoveryKind.INCOMPLETE_PURGE:
            if self.completion_audit_sequence is not None:
                raise ValueError("incomplete purge cannot carry a completion audit")
        elif (
            self.completion_audit_sequence is None
            or self.completion_audit_sequence <= self.lease.intent_audit_sequence
        ):
            raise ValueError("trash cleanup requires its later completion audit")
        return self


class RetentionRepository(Protocol):
    """Transactional authority for retention state and audit transitions."""

    def list_expirable_media(
        self,
        run_id: str,
        expires_before: datetime,
        limit: int,
    ) -> tuple[str, ...]: ...

    def begin_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        expires_before: datetime,
        policy_version: str,
    ) -> PurgeLease | PurgeItemResult: ...

    def complete_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
        recovered: bool,
    ) -> PurgeItemResult: ...

    def claim_next_recovery(self, run_id: str) -> PurgeRecoveryCandidate | None: ...

    def mark_trash_cleaned(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
    ) -> None: ...

    def create_retention_hold(self, hold: RetentionHold) -> int: ...

    def release_retention_hold(self, run_id: str, hold_id: str) -> int: ...


class RetentionFileOps(Protocol):
    """Least-authority file operations needed by retention orchestration."""

    def stage_for_purge(self, lease: PurgeLease) -> None: ...

    def destroy_purged(self, lease: PurgeLease) -> None: ...


__all__ = [
    "PurgeLease",
    "PurgeRecoveryCandidate",
    "RetentionFileOps",
    "RetentionRepository",
]
