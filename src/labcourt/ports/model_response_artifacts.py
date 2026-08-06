"""Bounded authority boundary for M3 model-response orphan recovery."""

from __future__ import annotations

import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.recovery import recovery_source_token
from labcourt.contracts.references import require_reference_token

MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES = 255
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_AREAS = frozenset(
    {
        ModelResponseRecoveryArea.STAGED_RESPONSE,
        ModelResponseRecoveryArea.FINAL_RESPONSE,
        ModelResponseRecoveryArea.JOURNAL,
    }
)
_EMPTY_OPERATION_AREAS = frozenset(
    {
        ModelResponseRecoveryArea.STAGED_RESPONSE,
        ModelResponseRecoveryArea.JOURNAL,
    }
)


@dataclass(frozen=True, slots=True)
class ModelResponseArtifactCandidate:
    """One reopened regular file with a sanitized logical authority."""

    run_id: str
    area: ModelResponseRecoveryArea
    authority_id: str
    source_token: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model response artifact run reference")
        if self.area not in _ARTIFACT_AREAS:
            raise ValueError("model response artifact candidate has an invalid area")
        for value, name in (
            (self.authority_id, "authority id"),
            (self.source_token, "source token"),
            (self.content_sha256, "content hash"),
        ):
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"model response artifact {name} must be a SHA-256 digest")
        source_relative = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                f".staging/{self.run_id}/model-response-{self.authority_id}/response.json"
            ),
            ModelResponseRecoveryArea.FINAL_RESPONSE: (
                f"{self.run_id}/model_responses/{self.authority_id}.json"
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                f".staging/{self.run_id}/model-request-{self.authority_id}/receipt.json"
            ),
        }[self.area]
        if recovery_source_token(source_relative) != self.source_token:
            raise ValueError("model response artifact token must bind its controlled locator")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or not 0 <= self.size_bytes <= MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
        ):
            raise ValueError("model response artifact size is outside its hard limit")

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.area.value, self.source_token


@dataclass(frozen=True, slots=True)
class ModelResponseEmptyOperationCandidate:
    """One exact empty response/journal operation eligible for age-gated removal."""

    run_id: str
    area: ModelResponseRecoveryArea
    authority_id: str
    source_token: str

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model response empty operation run reference")
        if self.area not in _EMPTY_OPERATION_AREAS:
            raise ValueError("model response empty operation has an invalid area")
        for value, name in (
            (self.authority_id, "authority id"),
            (self.source_token, "source token"),
        ):
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"model response empty operation {name} must be a SHA-256 digest")
        source_relative = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                f".staging/{self.run_id}/model-response-{self.authority_id}"
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                f".staging/{self.run_id}/model-request-{self.authority_id}"
            ),
        }[self.area]
        if recovery_source_token(source_relative) != self.source_token:
            raise ValueError(
                "model response empty operation token must bind its controlled locator"
            )

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.area.value, self.source_token


@dataclass(frozen=True, slots=True)
class ModelResponseArtifactScan:
    """Stable bounded discovery; incomplete scans authorize no quarantine."""

    run_id: str
    max_items: int
    max_file_bytes: int
    max_total_bytes: int
    bytes_scanned: int
    candidates: tuple[ModelResponseArtifactCandidate, ...]
    anomalies: tuple[ModelResponseRecoveryItem, ...]
    complete: bool
    cleanup_candidates: tuple[ModelResponseEmptyOperationCandidate, ...] = ()
    budget_exhaustions: tuple[ModelResponseRecoveryItem, ...] = ()

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model response artifact scan run reference")
        if (
            not isinstance(self.max_items, int)
            or isinstance(self.max_items, bool)
            or not 1 <= self.max_items <= MAX_MODEL_RESPONSE_RECOVERY_ITEMS
        ):
            raise ValueError("model response artifact max_items is outside its hard limit")
        if (
            not isinstance(self.max_file_bytes, int)
            or isinstance(self.max_file_bytes, bool)
            or not 1 <= self.max_file_bytes <= MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
        ):
            raise ValueError("model response artifact file-byte budget is outside its hard limit")
        if (
            not isinstance(self.max_total_bytes, int)
            or isinstance(self.max_total_bytes, bool)
            or not self.max_file_bytes
            <= self.max_total_bytes
            <= MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES
        ):
            raise ValueError("model response artifact total-byte budget is outside its hard limit")
        if (
            not isinstance(self.bytes_scanned, int)
            or isinstance(self.bytes_scanned, bool)
            or not 0 <= self.bytes_scanned <= self.max_total_bytes
        ):
            raise ValueError("model response artifact bytes scanned exceed their budget")
        if not isinstance(self.candidates, tuple) or any(
            not isinstance(candidate, ModelResponseArtifactCandidate)
            for candidate in self.candidates
        ):
            raise TypeError("model response artifact candidates must be a tuple")
        if not isinstance(self.anomalies, tuple) or any(
            not isinstance(item, ModelResponseRecoveryItem) for item in self.anomalies
        ):
            raise TypeError("model response artifact anomalies must be a tuple")
        if not isinstance(self.cleanup_candidates, tuple) or any(
            not isinstance(candidate, ModelResponseEmptyOperationCandidate)
            for candidate in self.cleanup_candidates
        ):
            raise TypeError("model response empty-operation candidates must be a tuple")
        if not isinstance(self.budget_exhaustions, tuple) or any(
            not isinstance(item, ModelResponseRecoveryItem) for item in self.budget_exhaustions
        ):
            raise TypeError("model response artifact budget exhaustions must be a tuple")
        if type(self.complete) is not bool:
            raise TypeError("model response artifact complete flag must be a boolean")
        if (
            any(candidate.run_id != self.run_id for candidate in self.candidates)
            or any(item.run_id != self.run_id for item in self.anomalies)
            or any(candidate.run_id != self.run_id for candidate in self.cleanup_candidates)
            or any(item.run_id != self.run_id for item in self.budget_exhaustions)
        ):
            raise ValueError("model response artifact scan entries belong to another run")
        if any(
            item.area not in _ARTIFACT_AREAS
            or item.disposition != ModelResponseRecoveryDisposition.ANOMALY
            for item in self.anomalies
        ):
            raise ValueError("model response artifact scan has a non-artifact anomaly")
        if any(
            item.area not in _ARTIFACT_AREAS
            or item.disposition != ModelResponseRecoveryDisposition.RETAINED
            or item.reason_code != ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED
            for item in self.budget_exhaustions
        ):
            raise ValueError("model response artifact scan has an invalid budget exhaustion")
        if self.complete and self.budget_exhaustions:
            raise ValueError("complete model response artifact scan exhausted its byte budget")
        if sum(candidate.size_bytes for candidate in self.candidates) > self.bytes_scanned:
            raise ValueError("model response artifact candidate bytes exceed bytes scanned")
        observed = (
            len(self.candidates)
            + len(self.cleanup_candidates)
            + len(self.anomalies)
            + len(self.budget_exhaustions)
        )
        if observed > self.max_items:
            raise ValueError("model response artifact scan exceeds its item budget")
        candidate_keys = tuple(candidate.sort_key for candidate in self.candidates)
        anomaly_keys = tuple((item.area.value, item.source_token or "") for item in self.anomalies)
        cleanup_keys = tuple(candidate.sort_key for candidate in self.cleanup_candidates)
        budget_keys = tuple(
            (item.area.value, item.source_token or "") for item in self.budget_exhaustions
        )
        if candidate_keys != tuple(sorted(candidate_keys)):
            raise ValueError("model response artifact candidates must use stable order")
        if cleanup_keys != tuple(sorted(cleanup_keys)):
            raise ValueError("model response empty-operation candidates must use stable order")
        if anomaly_keys != tuple(sorted(anomaly_keys)):
            raise ValueError("model response artifact anomalies must use stable order")
        if budget_keys != tuple(sorted(budget_keys)):
            raise ValueError("model response artifact budget exhaustions must use stable order")
        sources = tuple((*candidate_keys, *cleanup_keys, *anomaly_keys, *budget_keys))
        if len(sources) != len(set(sources)):
            raise ValueError("model response artifact scan sources must be unique")

    @property
    def artifacts_scanned(self) -> int:
        return (
            len(self.candidates)
            + len(self.cleanup_candidates)
            + len(self.anomalies)
            + len(self.budget_exhaustions)
        )


class ModelResponseArtifactReferenceRepository(Protocol):
    def model_response_is_referenced(
        self,
        run_id: str,
        response_id: str,
        content_sha256: str,
    ) -> bool: ...


class ModelResponseArtifactRecoveryFence(Protocol):
    """Exclude new M3 writes while claims are rescanned and artifacts mutate."""

    def model_response_artifact_recovery_fence(
        self,
        run_id: str,
    ) -> AbstractContextManager[None]: ...


class ModelResponseArtifactFileOps(Protocol):
    def discover_model_response_artifacts(
        self,
        run_id: str,
        max_items: int,
        max_name_bytes: int,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> ModelResponseArtifactScan: ...

    def quarantine_model_response_artifact(
        self,
        candidate: ModelResponseArtifactCandidate,
        not_modified_after: datetime,
        max_file_bytes: int,
    ) -> ModelResponseRecoveryItem: ...

    def cleanup_empty_model_response_operation(
        self,
        candidate: ModelResponseEmptyOperationCandidate,
        not_modified_after: datetime,
    ) -> ModelResponseRecoveryItem: ...


__all__ = [
    "MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES",
    "MAX_MODEL_RESPONSE_RECOVERY_ITEMS",
    "MAX_MODEL_RESPONSE_RECOVERY_NAME_BYTES",
    "MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES",
    "ModelResponseArtifactCandidate",
    "ModelResponseArtifactFileOps",
    "ModelResponseArtifactRecoveryFence",
    "ModelResponseArtifactReferenceRepository",
    "ModelResponseArtifactScan",
    "ModelResponseEmptyOperationCandidate",
]
