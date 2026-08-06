"""Typed, non-sensitive M3 model-response recovery reports."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.paths import require_safe_relative_posix_path
from labcourt.contracts.recovery import StartupRecoveryReport, recovery_source_token
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.screening import derive_model_response_id

MAX_MODEL_CALL_RECOVERY_ITEMS = 10_000
MAX_MODEL_RESPONSE_RECOVERY_ITEMS = 1_000
MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES = 262_144
MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES = (
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS * MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
)


class ModelResponseRecoveryArea(StrEnum):
    MODEL_CALL = "MODEL_CALL"
    STAGED_RESPONSE = "STAGED_RESPONSE"
    FINAL_RESPONSE = "FINAL_RESPONSE"
    JOURNAL = "JOURNAL"


class ModelResponseRecoveryDisposition(StrEnum):
    VERIFIED = "VERIFIED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DEFERRED = "DEFERRED"
    RETAINED = "RETAINED"
    QUARANTINED = "QUARANTINED"
    CLEANED = "CLEANED"
    ANOMALY = "ANOMALY"


class ModelResponseRecoveryReason(StrEnum):
    ACTIVE_LEASE_UNEXPIRED = "ACTIVE_LEASE_UNEXPIRED"
    ACTIVE_EXPIRED_NO_JOURNAL = "ACTIVE_EXPIRED_NO_JOURNAL"
    CLAIM_RACE_LOST = "CLAIM_RACE_LOST"
    CLAIM_SCAN_INCOMPLETE = "CLAIM_SCAN_INCOMPLETE"
    CLAIM_RECOVERY_SUPPRESSED = "CLAIM_RECOVERY_SUPPRESSED"
    JOURNAL_ACKNOWLEDGED = "JOURNAL_ACKNOWLEDGED"
    JOURNAL_ALREADY_ABSENT = "JOURNAL_ALREADY_ABSENT"
    ORPHAN_STAGE_QUARANTINED = "ORPHAN_STAGE_QUARANTINED"
    ORPHAN_FINAL_QUARANTINED = "ORPHAN_FINAL_QUARANTINED"
    ORPHAN_JOURNAL_QUARANTINED = "ORPHAN_JOURNAL_QUARANTINED"
    EMPTY_OPERATION_CLEANED = "EMPTY_OPERATION_CLEANED"
    MINIMUM_AGE_NOT_MET = "MINIMUM_AGE_NOT_MET"
    DATABASE_REFERENCED_ARTIFACT = "DATABASE_REFERENCED_ARTIFACT"
    ARTIFACT_SCAN_INCOMPLETE = "ARTIFACT_SCAN_INCOMPLETE"
    ARTIFACT_FILE_BYTES_EXCEEDED = "ARTIFACT_FILE_BYTES_EXCEEDED"
    ARTIFACT_TOTAL_BYTES_EXHAUSTED = "ARTIFACT_TOTAL_BYTES_EXHAUSTED"
    CLAIM_AUTHORITY_INVALID = "CLAIM_AUTHORITY_INVALID"
    JOURNAL_INTEGRITY_FAILURE = "JOURNAL_INTEGRITY_FAILURE"
    RESPONSE_INTEGRITY_FAILURE = "RESPONSE_INTEGRITY_FAILURE"
    RESPONSE_CONFLICT = "RESPONSE_CONFLICT"
    DATABASE_OBSERVATION_CONFLICT = "DATABASE_OBSERVATION_CONFLICT"
    CONTENT_IDENTITY_MISMATCH = "CONTENT_IDENTITY_MISMATCH"
    ENTRY_CHANGED_DURING_RECOVERY = "ENTRY_CHANGED_DURING_RECOVERY"
    UNSAFE_FILESYSTEM_ENTRY = "UNSAFE_FILESYSTEM_ENTRY"
    UNKNOWN_ENTRY_SHAPE = "UNKNOWN_ENTRY_SHAPE"
    ORPHAN_MUTATION_SUPPRESSED = "ORPHAN_MUTATION_SUPPRESSED"


class ModelResponseArtifactPhase(StrEnum):
    COMPLETED = "COMPLETED"
    DEFERRED_ACTIVE_CLAIM = "DEFERRED_ACTIVE_CLAIM"
    SUPPRESSED_CLAIM_SCAN_INCOMPLETE = "SUPPRESSED_CLAIM_SCAN_INCOMPLETE"
    SUPPRESSED_INTEGRITY_FAILURE = "SUPPRESSED_INTEGRITY_FAILURE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


_CLAIM_OUTCOMES: dict[
    ModelResponseRecoveryReason,
    ModelResponseRecoveryDisposition,
] = {
    ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED: (ModelResponseRecoveryDisposition.DEFERRED),
    ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL: (
        ModelResponseRecoveryDisposition.DEFERRED
    ),
    ModelResponseRecoveryReason.CLAIM_RACE_LOST: ModelResponseRecoveryDisposition.DEFERRED,
    ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE: (ModelResponseRecoveryDisposition.DEFERRED),
    ModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED: (
        ModelResponseRecoveryDisposition.DEFERRED
    ),
    ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED: (
        ModelResponseRecoveryDisposition.ACKNOWLEDGED
    ),
    ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT: (ModelResponseRecoveryDisposition.VERIFIED),
    ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID: (ModelResponseRecoveryDisposition.ANOMALY),
    ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE: (
        ModelResponseRecoveryDisposition.ANOMALY
    ),
    ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE: (
        ModelResponseRecoveryDisposition.ANOMALY
    ),
    ModelResponseRecoveryReason.RESPONSE_CONFLICT: ModelResponseRecoveryDisposition.ANOMALY,
    ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT: (
        ModelResponseRecoveryDisposition.ANOMALY
    ),
}
_RESPONSE_REQUIRED_REASONS = frozenset(
    {
        ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
    }
)
_ACTIVE_DEFERRED_REASONS = frozenset(
    {
        ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
        ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL,
        ModelResponseRecoveryReason.CLAIM_RACE_LOST,
    }
)
_ATTENTION_DEFERRED_REASONS = frozenset({ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL})
_OPAQUE_CLAIM_REASONS = frozenset(
    {
        ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
        ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
    }
)
_ARTIFACT_QUARANTINE_MATRIX = {
    ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED: (
        ModelResponseRecoveryArea.STAGED_RESPONSE
    ),
    ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED: (
        ModelResponseRecoveryArea.FINAL_RESPONSE
    ),
    ModelResponseRecoveryReason.ORPHAN_JOURNAL_QUARANTINED: (ModelResponseRecoveryArea.JOURNAL),
}
_ARTIFACT_RETAINED_REASONS = frozenset(
    {
        ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
        ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT,
        ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
        ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
        ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
    }
)
_ARTIFACT_ANOMALY_REASONS = frozenset(
    {
        ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE,
        ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE,
        ModelResponseRecoveryReason.RESPONSE_CONFLICT,
        ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
        ModelResponseRecoveryReason.CONTENT_IDENTITY_MISMATCH,
        ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY,
        ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY,
        ModelResponseRecoveryReason.UNKNOWN_ENTRY_SHAPE,
        ModelResponseRecoveryReason.ARTIFACT_FILE_BYTES_EXCEEDED,
    }
)
_ARTIFACT_REASON_AREAS: dict[
    ModelResponseRecoveryReason,
    frozenset[ModelResponseRecoveryArea],
] = {
    ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED: frozenset(
        {ModelResponseRecoveryArea.STAGED_RESPONSE}
    ),
    ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED: frozenset(
        {ModelResponseRecoveryArea.FINAL_RESPONSE}
    ),
    ModelResponseRecoveryReason.ORPHAN_JOURNAL_QUARANTINED: frozenset(
        {ModelResponseRecoveryArea.JOURNAL}
    ),
    ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT: frozenset(
        {ModelResponseRecoveryArea.FINAL_RESPONSE}
    ),
    ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE: frozenset(
        {ModelResponseRecoveryArea.JOURNAL}
    ),
    ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
        }
    ),
    ModelResponseRecoveryReason.RESPONSE_CONFLICT: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.CONTENT_IDENTITY_MISMATCH: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
        }
    ),
    ModelResponseRecoveryReason.ENTRY_CHANGED_DURING_RECOVERY: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.UNSAFE_FILESYSTEM_ENTRY: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.UNKNOWN_ENTRY_SHAPE: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
    ModelResponseRecoveryReason.ARTIFACT_FILE_BYTES_EXCEEDED: frozenset(
        {
            ModelResponseRecoveryArea.STAGED_RESPONSE,
            ModelResponseRecoveryArea.FINAL_RESPONSE,
            ModelResponseRecoveryArea.JOURNAL,
        }
    ),
}


class ModelResponseRecoveryItem(FrozenContractModel):
    """One stable outcome without owner tokens, host paths, or response bytes."""

    run_id: ReferenceToken
    area: ModelResponseRecoveryArea
    request_id: Sha256Hex | None = None
    response_id: Sha256Hex | None = None
    response_content_sha256: Sha256Hex | None = None
    source_token: Sha256Hex | None = None
    content_sha256: Sha256Hex | None = None
    quarantine_relative_path: str | None = None
    disposition: ModelResponseRecoveryDisposition
    reason_code: ModelResponseRecoveryReason

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "model response recovery run reference")

    @field_validator("quarantine_relative_path")
    @classmethod
    def validate_quarantine_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_safe_relative_posix_path(value)

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        authority = self.request_id or self.source_token or ""
        return (
            self.area.value,
            authority,
            self.response_id or "",
            self.reason_code.value,
        )

    @model_validator(mode="after")
    def validate_outcome_matrix(self) -> Self:
        if self.area == ModelResponseRecoveryArea.MODEL_CALL:
            if (self.request_id is None) == (self.source_token is None):
                raise ValueError(
                    "model-call recovery requires exactly one canonical or opaque authority"
                )
            if self.source_token is not None and self.reason_code not in _OPAQUE_CLAIM_REASONS:
                raise ValueError("only malformed claim authority may use an opaque source token")
            if self.source_token is not None and (
                self.response_id is not None or self.response_content_sha256 is not None
            ):
                raise ValueError("opaque claim authority cannot bind a response")
            if self.content_sha256 is not None or self.quarantine_relative_path is not None:
                raise ValueError("model-call recovery cannot carry artifact file identity")
            expected = _CLAIM_OUTCOMES.get(self.reason_code)
            if expected is None or self.disposition != expected:
                raise ValueError("model-call recovery reason conflicts with its disposition")
            if self.reason_code in _RESPONSE_REQUIRED_REASONS and self.response_id is None:
                raise ValueError("completed model-call recovery requires a response id")
            if (
                self.reason_code
                in {
                    ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
                    ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL,
                    ModelResponseRecoveryReason.CLAIM_RACE_LOST,
                    ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE,
                    ModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED,
                }
                and self.response_id is not None
            ):
                raise ValueError("active model-call recovery cannot claim a response id")
            if (self.response_id is None) != (self.response_content_sha256 is None):
                raise ValueError(
                    "model-call response identity requires both response and content hashes"
                )
            if (
                self.response_id is not None
                and self.response_content_sha256 is not None
                and self.request_id is not None
                and derive_model_response_id(
                    self.run_id,
                    self.request_id,
                    self.response_content_sha256,
                )
                != self.response_id
            ):
                raise ValueError("model-call response identity is not request/content bound")
            return self

        if (
            self.source_token is None
            or self.request_id is not None
            or self.response_id is not None
            or self.response_content_sha256 is not None
        ):
            raise ValueError("artifact recovery requires only an opaque source token")
        allowed_areas = _ARTIFACT_REASON_AREAS.get(self.reason_code)
        if allowed_areas is None or self.area not in allowed_areas:
            raise ValueError("artifact recovery reason conflicts with its area")
        quarantine_area = _ARTIFACT_QUARANTINE_MATRIX.get(self.reason_code)
        if quarantine_area is not None:
            if (
                self.disposition != ModelResponseRecoveryDisposition.QUARANTINED
                or self.area != quarantine_area
            ):
                raise ValueError("artifact quarantine reason conflicts with its area")
            if self.content_sha256 is None or self.quarantine_relative_path is None:
                raise ValueError(
                    "artifact quarantine requires content identity and controlled location"
                )
            self._validate_controlled_quarantine()
            return self
        if self.quarantine_relative_path is not None:
            raise ValueError("only quarantined artifact recovery may carry a location")
        if self.reason_code == ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED:
            if (
                self.disposition != ModelResponseRecoveryDisposition.CLEANED
                or self.content_sha256 is not None
            ):
                raise ValueError("cleaned model-response recovery requires an empty operation")
            return self
        if self.reason_code in _ARTIFACT_RETAINED_REASONS:
            if self.disposition != ModelResponseRecoveryDisposition.RETAINED:
                raise ValueError("retained artifact recovery requires a retained reason")
            if (
                self.reason_code == ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT
                and self.content_sha256 is None
            ):
                raise ValueError("database-referenced response requires content identity")
            if (
                self.content_sha256 is None
                and self.reason_code == ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET
                and self.area
                not in {
                    ModelResponseRecoveryArea.STAGED_RESPONSE,
                    ModelResponseRecoveryArea.JOURNAL,
                }
            ):
                raise ValueError("content-free age retention requires an empty operation area")
            return self
        if (
            self.reason_code not in _ARTIFACT_ANOMALY_REASONS
            or self.disposition != ModelResponseRecoveryDisposition.ANOMALY
        ):
            raise ValueError("artifact recovery reason conflicts with its disposition")
        return self

    def _validate_controlled_quarantine(self) -> None:
        assert self.content_sha256 is not None
        assert self.quarantine_relative_path is not None
        parts = self.quarantine_relative_path.split("/")
        if len(parts) != 5 or parts[:3] != [
            ".quarantine",
            self.run_id,
            "model_responses",
        ]:
            raise ValueError("artifact quarantine location is not controlled")
        area_name = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: "staging",
            ModelResponseRecoveryArea.FINAL_RESPONSE: "final",
            ModelResponseRecoveryArea.JOURNAL: "journal",
        }.get(self.area)
        if area_name is None or parts[3] != area_name:
            raise ValueError("artifact quarantine location conflicts with its area")
        match = re.fullmatch(
            rf"(?P<authority>[0-9a-f]{{64}})-{self.content_sha256}\.json",
            parts[4],
        )
        if match is None:
            raise ValueError("artifact quarantine location conflicts with content identity")
        authority = match.group("authority")
        source_relative = {
            ModelResponseRecoveryArea.STAGED_RESPONSE: (
                f".staging/{self.run_id}/model-response-{authority}/response.json"
            ),
            ModelResponseRecoveryArea.FINAL_RESPONSE: (
                f"{self.run_id}/model_responses/{authority}.json"
            ),
            ModelResponseRecoveryArea.JOURNAL: (
                f".staging/{self.run_id}/model-request-{authority}/receipt.json"
            ),
        }[self.area]
        if recovery_source_token(source_relative) != self.source_token:
            raise ValueError("artifact quarantine location conflicts with its source token")


class ModelResponseRecoveryReport(FrozenContractModel):
    """Bounded claim and artifact recovery with explicit incomplete phases."""

    run_id: ReferenceToken
    started_at: datetime
    artifact_not_modified_after: datetime
    claim_limit: int = Field(gt=0, le=MAX_MODEL_CALL_RECOVERY_ITEMS, strict=True)
    claims_scanned: int = Field(ge=0, strict=True)
    claim_scan_complete: bool = Field(strict=True)
    artifact_limit: int = Field(
        gt=0,
        le=MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
        strict=True,
    )
    artifacts_scanned: int = Field(ge=0, strict=True)
    artifact_file_bytes_limit: int = Field(
        gt=0,
        le=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        strict=True,
    )
    artifact_total_bytes_limit: int = Field(
        gt=0,
        le=MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
        strict=True,
    )
    artifact_bytes_scanned: int = Field(ge=0, strict=True)
    artifact_scan_complete: bool = Field(strict=True)
    artifact_phase: ModelResponseArtifactPhase
    items: tuple[ModelResponseRecoveryItem, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "model response recovery report run reference")

    @field_validator("started_at")
    @classmethod
    def validate_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
            raise ValueError("model response recovery time must use timezone-aware UTC")
        return value

    @field_validator("artifact_not_modified_after")
    @classmethod
    def validate_artifact_cutoff(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
            raise ValueError("model response recovery cutoff must use timezone-aware UTC")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_status(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        attention_present = "requires_attention" in payload
        passed_present = "passed" in payload
        claimed_attention = payload.pop("requires_attention", None)
        claimed_passed = payload.pop("passed", None)
        report = handler(payload)
        if attention_present and (
            type(claimed_attention) is not bool or claimed_attention != report.requires_attention
        ):
            raise ValueError(
                "serialized model response recovery attention conflicts with its results"
            )
        if passed_present and (type(claimed_passed) is not bool or claimed_passed != report.passed):
            raise ValueError("serialized model response recovery passed conflicts with its results")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def requires_attention(self) -> bool:
        return (
            not self.claim_scan_complete
            or self.artifact_phase
            in {
                ModelResponseArtifactPhase.SUPPRESSED_CLAIM_SCAN_INCOMPLETE,
                ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
                ModelResponseArtifactPhase.BUDGET_EXHAUSTED,
            }
            or any(
                item.disposition == ModelResponseRecoveryDisposition.ANOMALY for item in self.items
            )
            or any(
                item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
                for item in self.items
            )
            or any(item.reason_code in _ATTENTION_DEFERRED_REASONS for item in self.items)
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.requires_attention

    @model_validator(mode="after")
    def validate_scope_budgets_and_phase(self) -> Self:
        if self.artifact_not_modified_after >= self.started_at:
            raise ValueError("model response recovery cutoff must be earlier than startup time")
        if self.claims_scanned > self.claim_limit:
            raise ValueError("model response claim scan exceeds its hard limit")
        if self.artifacts_scanned > self.artifact_limit:
            raise ValueError("model response artifact scan exceeds its hard limit")
        if self.artifact_total_bytes_limit < self.artifact_file_bytes_limit:
            raise ValueError("model response aggregate byte limit must cover one file")
        if self.artifact_bytes_scanned > self.artifact_total_bytes_limit:
            raise ValueError("model response artifact scan exceeds its byte limit")
        if any(item.run_id != self.run_id for item in self.items):
            raise ValueError("model response recovery items must belong to its run")
        keys = tuple(item.sort_key for item in self.items)
        authority_keys = tuple(key[:2] for key in keys)
        if len(authority_keys) != len(set(authority_keys)):
            raise ValueError("model response recovery items must be unique by authority")
        if keys != tuple(sorted(keys)):
            raise ValueError("model response recovery items must use stable order")

        model_call_items = sum(
            item.area == ModelResponseRecoveryArea.MODEL_CALL for item in self.items
        )
        artifact_items = len(self.items) - model_call_items
        if model_call_items != self.claims_scanned:
            raise ValueError("claim scan count must equal its typed recovery outcomes")
        if artifact_items != self.artifacts_scanned:
            raise ValueError("artifact scan count must equal its typed recovery outcomes")

        active_deferred = any(item.reason_code in _ACTIVE_DEFERRED_REASONS for item in self.items)
        anomaly = any(
            item.disposition == ModelResponseRecoveryDisposition.ANOMALY for item in self.items
        )
        claim_anomaly = any(
            item.area == ModelResponseRecoveryArea.MODEL_CALL
            and item.disposition == ModelResponseRecoveryDisposition.ANOMALY
            for item in self.items
        )
        quarantined = any(
            item.disposition == ModelResponseRecoveryDisposition.QUARANTINED for item in self.items
        )
        cleaned = any(
            item.disposition == ModelResponseRecoveryDisposition.CLEANED for item in self.items
        )
        mutation_suppressed = any(
            item.reason_code == ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED
            for item in self.items
        )
        claim_scan_deferred = any(
            item.reason_code == ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
            for item in self.items
        )
        claim_recovery_suppressed = any(
            item.reason_code == ModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED
            for item in self.items
        )
        artifact_scan_deferred = any(
            item.reason_code == ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE
            for item in self.items
        )
        artifact_byte_budget_exhausted = any(
            item.reason_code == ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED
            for item in self.items
        )
        if not self.claim_scan_complete:
            if (
                self.claims_scanned != self.claim_limit
                or self.artifact_phase
                != ModelResponseArtifactPhase.SUPPRESSED_CLAIM_SCAN_INCOMPLETE
                or self.artifact_scan_complete
                or self.artifacts_scanned != 0
                or self.artifact_bytes_scanned != 0
                or any(
                    item.area == ModelResponseRecoveryArea.MODEL_CALL
                    and item.disposition != ModelResponseRecoveryDisposition.ANOMALY
                    and item.reason_code != ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
                    for item in self.items
                )
            ):
                raise ValueError("incomplete claim scan must suppress artifact recovery")
            return self
        if claim_scan_deferred:
            raise ValueError("complete claim scan cannot contain scan-deferred outcomes")
        if claim_recovery_suppressed and not claim_anomaly:
            raise ValueError("claim recovery suppression requires a claim anomaly")
        if self.artifact_scan_complete and (
            artifact_scan_deferred or artifact_byte_budget_exhausted
        ):
            raise ValueError("complete artifact scan cannot contain scan-deferred outcomes")
        if quarantined and (
            self.artifact_phase
            not in {
                ModelResponseArtifactPhase.COMPLETED,
                ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
            }
            or not self.claim_scan_complete
            or not self.artifact_scan_complete
        ):
            raise ValueError("artifact quarantine requires complete safe claim and artifact scans")
        if cleaned and (
            self.artifact_phase
            not in {
                ModelResponseArtifactPhase.COMPLETED,
                ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
            }
            or not self.claim_scan_complete
            or not self.artifact_scan_complete
        ):
            raise ValueError(
                "empty-operation cleanup requires complete safe claim and artifact scans"
            )
        if not self.artifact_scan_complete:
            artifact_non_anomalies = tuple(
                item
                for item in self.items
                if item.area != ModelResponseRecoveryArea.MODEL_CALL
                and item.disposition != ModelResponseRecoveryDisposition.ANOMALY
            )
            if self.artifact_phase == ModelResponseArtifactPhase.BUDGET_EXHAUSTED and any(
                item.reason_code
                not in {
                    ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
                    ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
                }
                for item in artifact_non_anomalies
            ):
                raise ValueError(
                    "incomplete clean artifact scan must retain every observed candidate"
                )
            if (
                self.artifact_phase == ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
                and any(
                    item.reason_code
                    not in {
                        ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
                        ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
                    }
                    for item in artifact_non_anomalies
                )
            ):
                raise ValueError(
                    "incomplete unsafe artifact scan must suppress every observed candidate"
                )
        if anomaly and (
            self.artifact_phase != ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
        ):
            raise ValueError("typed anomaly must suppress artifact mutation")
        if claim_anomaly and (
            self.artifacts_scanned != 0
            or self.artifact_bytes_scanned != 0
            or self.artifact_scan_complete
        ):
            raise ValueError("claim anomaly must suppress the artifact scan entirely")
        if (
            not anomaly
            and active_deferred
            and self.artifact_phase != ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM
        ):
            raise ValueError("unresolved active claim must defer artifact mutation")
        if mutation_suppressed and (
            self.artifact_phase != ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE
        ):
            raise ValueError("suppressed orphan mutation cannot be reported as complete")
        if self.artifact_phase == ModelResponseArtifactPhase.COMPLETED:
            if not self.artifact_scan_complete or active_deferred or anomaly:
                raise ValueError("completed artifact recovery conflicts with observed state")
            return self
        if self.artifact_phase == ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM:
            if (
                not active_deferred
                or anomaly
                or self.artifact_scan_complete
                or self.artifacts_scanned != 0
                or self.artifact_bytes_scanned != 0
            ):
                raise ValueError("active-claim deferral conflicts with its scan state")
            return self
        if self.artifact_phase == ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE:
            if not anomaly:
                raise ValueError("integrity suppression requires a typed anomaly")
            return self
        if self.artifact_phase == ModelResponseArtifactPhase.BUDGET_EXHAUSTED:
            if self.artifact_scan_complete or active_deferred or anomaly or quarantined or cleaned:
                raise ValueError("artifact budget exhaustion requires a full observed limit")
            return self
        raise ValueError("claim-complete report uses an invalid artifact phase")


class MaintenanceRecoveryReport(FrozenContractModel):
    """Versioned envelope that preserves the frozen M2 startup report unchanged."""

    run_id: ReferenceToken
    started_at: datetime
    storage_report: StartupRecoveryReport
    model_response_report: ModelResponseRecoveryReport

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "maintenance recovery report run reference")

    @field_validator("started_at")
    @classmethod
    def validate_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
            raise ValueError("maintenance recovery time must use timezone-aware UTC")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_status(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        attention_present = "requires_attention" in payload
        passed_present = "passed" in payload
        claimed_attention = payload.pop("requires_attention", None)
        claimed_passed = payload.pop("passed", None)
        report = handler(payload)
        if attention_present and (
            type(claimed_attention) is not bool or claimed_attention != report.requires_attention
        ):
            raise ValueError("serialized maintenance recovery attention conflicts with results")
        if passed_present and (type(claimed_passed) is not bool or claimed_passed != report.passed):
            raise ValueError("serialized maintenance recovery passed conflicts with results")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def requires_attention(self) -> bool:
        return (
            self.storage_report.requires_attention or self.model_response_report.requires_attention
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.requires_attention

    @model_validator(mode="after")
    def validate_scope_and_time(self) -> Self:
        if (
            self.storage_report.run_id != self.run_id
            or self.model_response_report.run_id != self.run_id
        ):
            raise ValueError("maintenance recovery reports must belong to its run")
        if (
            self.storage_report.started_at != self.started_at
            or self.model_response_report.started_at != self.started_at
        ):
            raise ValueError("maintenance recovery reports must share one startup time")
        if self.storage_report.started_at.utcoffset() != timedelta(
            0
        ) or self.storage_report.orphan_report.not_modified_after.utcoffset() != timedelta(0):
            raise ValueError("maintenance storage recovery times must use UTC")
        return self


__all__ = [
    "MAX_MODEL_CALL_RECOVERY_ITEMS",
    "MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES",
    "MAX_MODEL_RESPONSE_RECOVERY_ITEMS",
    "MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES",
    "MaintenanceRecoveryReport",
    "ModelResponseArtifactPhase",
    "ModelResponseRecoveryArea",
    "ModelResponseRecoveryDisposition",
    "ModelResponseRecoveryItem",
    "ModelResponseRecoveryReason",
    "ModelResponseRecoveryReport",
]
