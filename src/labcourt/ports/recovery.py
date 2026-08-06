"""Least-authority boundaries for bounded staging and orphan recovery."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Protocol, Self

from pydantic import field_validator, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import RecoveryArea, RecoveryDisposition
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.recovery import RecoveryItemResult, recovery_source_token
from labcourt.contracts.references import ReferenceToken, require_reference_token

_STAGING_SOURCE = re.compile(r"^\.staging/(?P<run_id>[^/]+)/crop-[0-9a-f]{64}/media\.png$")
_EMPTY_STAGING_SOURCE = re.compile(r"^\.staging/(?P<run_id>[^/]+)/crop-[0-9a-f]{64}$")
_FINAL_SOURCE = re.compile(r"^(?P<run_id>[^/]+)/frames/(?P<media_sha256>[0-9a-f]{64})\.png$")
MAX_RECOVERY_ITEMS = 10_000
MAX_RECOVERY_DEPTH = 2
MAX_RECOVERY_NAME_BYTES = 255


class RecoveryCandidate(FrozenContractModel):
    """A handle-verified regular file eligible for an age-checked move."""

    run_id: ReferenceToken
    area: RecoveryArea
    source_relative_path: str
    source_token: Sha256Hex
    content_sha256: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "recovery candidate run_id")

    @field_validator("source_relative_path")
    @classmethod
    def validate_source_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_controlled_source(self) -> Self:
        if self.source_token != recovery_source_token(self.source_relative_path):
            raise ValueError("recovery candidate source token must bind its source locator")
        if self.area == RecoveryArea.STAGING:
            matched = _STAGING_SOURCE.fullmatch(self.source_relative_path)
            if matched is None or matched.group("run_id") != self.run_id:
                raise ValueError("staging recovery candidate must use the controlled shape")
        else:
            matched = _FINAL_SOURCE.fullmatch(self.source_relative_path)
            if (
                matched is None
                or matched.group("run_id") != self.run_id
                or matched.group("media_sha256") != self.content_sha256
            ):
                raise ValueError(
                    "final recovery candidate must use its content-addressed media locator"
                )
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.area.value, self.source_token


class StagingCleanupCandidate(FrozenContractModel):
    """One exact empty staging-operation directory eligible for non-recursive removal."""

    run_id: ReferenceToken
    source_relative_path: str
    source_token: Sha256Hex

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "staging cleanup candidate run_id")

    @field_validator("source_relative_path")
    @classmethod
    def validate_source_path(cls, value: str) -> str:
        return require_safe_relative_posix_path(value)

    @model_validator(mode="after")
    def validate_controlled_source(self) -> Self:
        matched = _EMPTY_STAGING_SOURCE.fullmatch(self.source_relative_path)
        if (
            matched is None
            or matched.group("run_id") != self.run_id
            or self.source_token != recovery_source_token(self.source_relative_path)
        ):
            raise ValueError("staging cleanup candidate must use the controlled empty shape")
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return RecoveryArea.STAGING.value, self.source_token


class RecoveryScan(FrozenContractModel):
    """A complete bounded discovery pass; no filesystem action has yet occurred."""

    run_id: ReferenceToken
    candidates: tuple[RecoveryCandidate, ...] = ()
    staging_cleanup_candidates: tuple[StagingCleanupCandidate, ...] = ()
    anomalies: tuple[RecoveryItemResult, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "recovery scan run_id")

    @model_validator(mode="after")
    def validate_scope_and_order(self) -> Self:
        if any(candidate.run_id != self.run_id for candidate in self.candidates):
            raise ValueError("recovery candidates must belong to the scan run")
        if any(candidate.run_id != self.run_id for candidate in self.staging_cleanup_candidates):
            raise ValueError("staging cleanup candidates must belong to the scan run")
        if any(
            item.run_id != self.run_id or item.disposition != RecoveryDisposition.ANOMALY
            for item in self.anomalies
        ):
            raise ValueError("recovery scan anomalies must belong to the scan run")

        candidate_keys = tuple(candidate.sort_key for candidate in self.candidates)
        cleanup_keys = tuple(candidate.sort_key for candidate in self.staging_cleanup_candidates)
        anomaly_keys = tuple(item.sort_key for item in self.anomalies)
        anomaly_source_keys = tuple(key[:2] for key in anomaly_keys)
        all_source_keys = candidate_keys + cleanup_keys + anomaly_source_keys
        if len(all_source_keys) != len(set(all_source_keys)):
            raise ValueError("recovery scan entries must be unique")
        if (
            candidate_keys != tuple(sorted(candidate_keys))
            or cleanup_keys != tuple(sorted(cleanup_keys))
            or anomaly_keys != tuple(sorted(anomaly_keys))
        ):
            raise ValueError("recovery scan entries must use stable order")
        return self


class OrphanReferenceRepository(Protocol):
    """Database reverse-reference query; implementations must remain run scoped."""

    def media_is_referenced(self, run_id: str, media_sha256: str) -> bool: ...


class OrphanRecoveryFileOps(Protocol):
    """Bounded discovery and one-file handle-verified quarantine operations."""

    def discover(
        self,
        run_id: str,
        max_items: int,
        max_depth: int,
        max_name_bytes: int,
    ) -> RecoveryScan: ...

    def quarantine(
        self,
        candidate: RecoveryCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult: ...

    def cleanup_empty_staging(
        self,
        candidate: StagingCleanupCandidate,
        not_modified_after: datetime,
    ) -> RecoveryItemResult: ...


__all__ = [
    "MAX_RECOVERY_DEPTH",
    "MAX_RECOVERY_ITEMS",
    "MAX_RECOVERY_NAME_BYTES",
    "OrphanRecoveryFileOps",
    "OrphanReferenceRepository",
    "RecoveryCandidate",
    "RecoveryScan",
    "StagingCleanupCandidate",
]
