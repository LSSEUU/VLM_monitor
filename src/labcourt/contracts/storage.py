"""Typed M2 artifact, closure, verification, and retention value contracts."""

from __future__ import annotations

import re
from typing import Literal, Self
from uuid import UUID

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    ClosureDefectCode,
    MediaAvailability,
    MediaType,
    PurgeDisposition,
    PurgeReasonCode,
    RetentionHoldKind,
    VerificationStatus,
)
from labcourt.contracts.frames import SHA256_PATTERN, Sha256Hex
from labcourt.contracts.references import (
    ReferenceToken,
    parse_frame_id,
    require_reference_token,
)

CLOSURE_VALIDATOR_VERSION: Literal["m2-closure-v1"] = "m2-closure-v1"
CONTENT_ADDRESSED_ARTIFACT_KINDS = frozenset(
    {
        ArtifactKind.CROP,
        ArtifactKind.MEDIA,
        ArtifactKind.EVIDENCE_PACK,
        ArtifactKind.MANIFEST,
        ArtifactKind.MODEL_RESPONSE,
        ArtifactKind.MODEL_REQUEST,
        ArtifactKind.PROMPT_MANIFEST,
        ArtifactKind.MODEL_PARSE_RECEIPT,
        ArtifactKind.PARSED_MODEL_OUTPUT,
        ArtifactKind.PROCEDURAL_REVIEW,
        ArtifactKind.MODEL_CACHE_ENTRY,
        ArtifactKind.SCREENING_RESULT,
        ArtifactKind.VERDICT,
        ArtifactKind.BACKLOG_ITEM,
    }
)
UUID_ARTIFACT_KINDS = frozenset({ArtifactKind.CASE, ArtifactKind.EVENT})

_SHA256 = re.compile(SHA256_PATTERN)
_HASH_DEFECT_CODES = frozenset(
    {
        ClosureDefectCode.SOURCE_HASH_MISMATCH,
        ClosureDefectCode.MEDIA_HASH_MISMATCH,
        ClosureDefectCode.PIXEL_HASH_MISMATCH,
        ClosureDefectCode.MANIFEST_MISMATCH,
    }
)
_CROSS_REFERENCE_DEFECT_CODES = frozenset(
    {
        ClosureDefectCode.CROSS_RUN_REFERENCE,
        ClosureDefectCode.CROSS_CASE_REFERENCE,
        ClosureDefectCode.CROSS_STREAM_FRAME,
    }
)
_UNAVAILABLE_WITHOUT_FILE_STATUSES = frozenset(
    {
        VerificationStatus.MISSING,
        VerificationStatus.PATH_BOUNDARY_VIOLATION,
        VerificationStatus.UNSAFE_LINK,
        VerificationStatus.NOT_REGULAR_FILE,
    }
)
_FULL_ACTUAL_STATUSES = frozenset(
    {
        VerificationStatus.SOURCE_HASH_MISMATCH,
        VerificationStatus.MEDIA_HASH_MISMATCH,
        VerificationStatus.SIZE_MISMATCH,
        VerificationStatus.PIXEL_HASH_MISMATCH,
        VerificationStatus.DIMENSION_MISMATCH,
    }
)
_RETENTION_OWNER_KINDS = {
    RetentionHoldKind.APPEAL: frozenset({ArtifactKind.APPEAL}),
    RetentionHoldKind.GOLD_SET: frozenset({ArtifactKind.DATASET}),
    RetentionHoldKind.CHALLENGE_SET: frozenset({ArtifactKind.DATASET}),
    RetentionHoldKind.MANUAL_LEGAL_HOLD: frozenset({ArtifactKind.CASE}),
}
_PURGED_REASONS = frozenset(
    {
        PurgeReasonCode.EXPIRED_AND_PURGED,
        PurgeReasonCode.RECOVERED_PURGE_COMPLETED,
    }
)
_RECOVERY_REASONS = frozenset(
    {
        PurgeReasonCode.PURGE_ALREADY_IN_PROGRESS,
        PurgeReasonCode.MEDIA_FILE_MISSING,
        PurgeReasonCode.MEDIA_INTEGRITY_FAILURE,
        PurgeReasonCode.WORKSPACE_OPERATION_FAILED,
        PurgeReasonCode.TRASH_CLEANUP_FAILED,
    }
)


def _require_canonical_uuid(value: str, name: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise ValueError(f"{name} must use lowercase canonical UUID form")
    return value


class ArtifactRef(FrozenContractModel):
    """A kind-discriminated reference with syntax fixed by the artifact kind."""

    kind: ArtifactKind
    artifact_id: str = Field(min_length=1, max_length=214)

    @model_validator(mode="after")
    def validate_artifact_id(self) -> ArtifactRef:
        if self.kind == ArtifactKind.FRAME:
            parse_frame_id(self.artifact_id)
        elif self.kind in CONTENT_ADDRESSED_ARTIFACT_KINDS:
            if _SHA256.fullmatch(self.artifact_id) is None:
                raise ValueError(f"{self.kind} artifact_id must be a lowercase SHA-256 digest")
        elif self.kind in UUID_ARTIFACT_KINDS:
            _require_canonical_uuid(self.artifact_id, f"{self.kind} artifact_id")
        else:
            require_reference_token(self.artifact_id, f"{self.kind} artifact_id")
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return self.kind.value, self.artifact_id


class ScopedArtifactRef(FrozenContractModel):
    """An artifact reference whose owning run is explicit and immutable."""

    run_id: ReferenceToken
    ref: ArtifactRef

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "scoped artifact run_id")

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.run_id, *self.ref.sort_key


class ClosureDefect(FrozenContractModel):
    """A typed closure failure; diagnostic context is explicit, never an open map."""

    code: ClosureDefectCode
    artifact_ref: ArtifactRef | None = None
    related_ref: ArtifactRef | None = None
    reason_code: ReferenceToken | None = None
    field: ReferenceToken | None = None
    role: ReferenceToken | None = None
    expected_sha256: Sha256Hex | None = None
    actual_sha256: Sha256Hex | None = None
    expected_width: int | None = Field(default=None, gt=0, strict=True)
    actual_width: int | None = Field(default=None, gt=0, strict=True)
    expected_height: int | None = Field(default=None, gt=0, strict=True)
    actual_height: int | None = Field(default=None, gt=0, strict=True)
    expected_size_bytes: int | None = Field(default=None, gt=0, strict=True)
    actual_size_bytes: int | None = Field(default=None, gt=0, strict=True)
    frame_index: int | None = Field(default=None, ge=0, strict=True)
    start_frame: int | None = Field(default=None, ge=0, strict=True)
    end_frame_exclusive: int | None = Field(default=None, gt=0, strict=True)

    @model_validator(mode="after")
    def validate_typed_context(self) -> ClosureDefect:
        if self.artifact_ref is None and self.related_ref is None:
            raise ValueError("closure defects require an artifact_ref or related_ref")
        if self.code in _CROSS_REFERENCE_DEFECT_CODES and (
            self.artifact_ref is None or self.related_ref is None
        ):
            raise ValueError("cross-reference defects require artifact_ref and related_ref")
        if self.code in _HASH_DEFECT_CODES:
            if self.expected_sha256 is None or self.actual_sha256 is None:
                raise ValueError("hash mismatch defects require expected and actual hashes")
            if self.expected_sha256 == self.actual_sha256:
                raise ValueError("hash mismatch defects require different hashes")
        if self.code == ClosureDefectCode.MEDIA_DIMENSION_MISMATCH:
            dimensions = (
                self.expected_width,
                self.actual_width,
                self.expected_height,
                self.actual_height,
            )
            if any(value is None for value in dimensions):
                raise ValueError("dimension mismatch requires expected and actual dimensions")
            if (
                self.expected_width == self.actual_width
                and self.expected_height == self.actual_height
            ):
                raise ValueError("dimension mismatch requires different dimensions")
        if self.code == ClosureDefectCode.MEDIA_SIZE_MISMATCH:
            if self.expected_size_bytes is None or self.actual_size_bytes is None:
                raise ValueError("size mismatch requires expected and actual sizes")
            if self.expected_size_bytes == self.actual_size_bytes:
                raise ValueError("size mismatch requires different sizes")
        interval = (self.start_frame, self.end_frame_exclusive)
        if (interval[0] is None) != (interval[1] is None):
            raise ValueError("closure frame intervals require both bounds")
        if (
            self.start_frame is not None
            and self.end_frame_exclusive is not None
            and self.start_frame >= self.end_frame_exclusive
        ):
            raise ValueError("closure frame interval must be non-empty")
        if self.code == ClosureDefectCode.FRAME_OUTSIDE_WINDOW and (
            self.frame_index is None or self.start_frame is None
        ):
            raise ValueError("frame-window defects require a frame and interval")
        return self

    @property
    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        artifact_key = self.artifact_ref.sort_key if self.artifact_ref is not None else ("", "")
        related_key = self.related_ref.sort_key if self.related_ref is not None else ("", "")
        context = self.model_dump(
            mode="json",
            exclude={"code", "artifact_ref", "related_ref"},
            exclude_none=True,
        )
        return (
            self.code.value,
            artifact_key[0],
            artifact_key[1],
            related_key[0],
            related_key[1],
            canonical_json(context),
        )


class ClosureReport(FrozenContractModel):
    validator_version: Literal["m2-closure-v1"] = CLOSURE_VALIDATOR_VERSION
    run_id: ReferenceToken
    root_ref: ArtifactRef
    manifest_id: Sha256Hex
    input_sha256: Sha256Hex
    checked_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    defects: tuple[ClosureDefect, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "closure run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_passed(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "passed" in payload
        claimed = payload.pop("passed", None)
        report = handler(payload)
        if claimed_present and not isinstance(claimed, bool):
            raise ValueError("serialized closure passed must be a boolean")
        if claimed_present and claimed != report.passed:
            raise ValueError("serialized closure passed does not match its defects")
        return report

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return not self.defects

    @model_validator(mode="after")
    def validate_scope_and_stable_order(self) -> ClosureReport:
        if self.root_ref.kind not in {ArtifactKind.CASE, ArtifactKind.EVIDENCE_PACK}:
            raise ValueError("closure root_ref must identify a case or evidence pack")
        if self.root_ref not in self.checked_refs:
            raise ValueError("closure checked_refs must include root_ref")

        checked_keys = tuple(item.sort_key for item in self.checked_refs)
        if len(checked_keys) != len(set(checked_keys)):
            raise ValueError("closure checked_refs must be unique")
        if checked_keys != tuple(sorted(checked_keys)):
            raise ValueError("closure checked_refs must use stable artifact order")

        defect_keys = tuple(item.sort_key for item in self.defects)
        if len(defect_keys) != len(set(defect_keys)):
            raise ValueError("closure defects must be unique")
        if defect_keys != tuple(sorted(defect_keys)):
            raise ValueError("closure defects must use stable defect order")
        return self


class ArtifactVerification(FrozenContractModel):
    """A media-specific verification result with a complete expected/actual matrix."""

    artifact_ref: ArtifactRef
    status: VerificationStatus
    availability: MediaAvailability
    media_type: MediaType
    expected_source_pixel_sha256: Sha256Hex
    actual_source_pixel_sha256: Sha256Hex | None = None
    expected_output_pixel_sha256: Sha256Hex
    actual_output_pixel_sha256: Sha256Hex | None = None
    expected_media_sha256: Sha256Hex
    actual_media_sha256: Sha256Hex | None = None
    expected_width: int = Field(gt=0, strict=True)
    actual_width: int | None = Field(default=None, gt=0, strict=True)
    expected_height: int = Field(gt=0, strict=True)
    actual_height: int | None = Field(default=None, gt=0, strict=True)
    expected_size_bytes: int = Field(gt=0, strict=True)
    actual_size_bytes: int | None = Field(default=None, gt=0, strict=True)
    reason_code: ReferenceToken | None = None

    @model_validator(mode="after")
    def validate_status_evidence(self) -> ArtifactVerification:
        artifact = self.artifact_ref
        if artifact.kind not in {ArtifactKind.CROP, ArtifactKind.MEDIA}:
            raise ValueError("artifact verification can target only crop or media artifacts")
        if (
            artifact.kind == ArtifactKind.MEDIA
            and artifact.artifact_id != self.expected_media_sha256
        ):
            raise ValueError("media artifact_id must equal expected_media_sha256")

        actual_values = (
            self.actual_source_pixel_sha256,
            self.actual_output_pixel_sha256,
            self.actual_media_sha256,
            self.actual_width,
            self.actual_height,
            self.actual_size_bytes,
        )
        all_actual = all(value is not None for value in actual_values)
        no_actual = all(value is None for value in actual_values)
        current_actual_values = actual_values[1:]
        all_current_actual = all(value is not None for value in current_actual_values)

        if self.status == VerificationStatus.PURGED_BY_RETENTION:
            if self.availability != MediaAvailability.PURGED_BY_RETENTION:
                raise ValueError("purged verification requires purged media availability")
            if not no_actual:
                raise ValueError("purged media must keep expected facts and clear all actual facts")
            return self
        if self.availability == MediaAvailability.PURGED_BY_RETENTION:
            raise ValueError("purged availability requires PURGED_BY_RETENTION status")

        if self.status == VerificationStatus.VERIFIED:
            if self.availability != MediaAvailability.AVAILABLE:
                raise ValueError("verified media must be available")
            if not all_actual:
                raise ValueError("verified media requires the complete actual field matrix")
            if not self._all_expected_values_match():
                raise ValueError("verified media requires every expected and actual value to match")
        elif self.status == VerificationStatus.CURRENT_MEDIA_VERIFIED:
            if self.availability != MediaAvailability.AVAILABLE:
                raise ValueError("current-media verification requires available media")
            if self.actual_source_pixel_sha256 is not None or not all_current_actual:
                raise ValueError(
                    "current-media verification requires current actuals without source replay"
                )
            if not self._all_expected_current_values_match():
                raise ValueError("current-media verification requires every current value to match")
        elif self.status in _UNAVAILABLE_WITHOUT_FILE_STATUSES:
            if not no_actual:
                raise ValueError(f"{self.status} cannot carry actual media facts")
        elif self.status in _FULL_ACTUAL_STATUSES:
            if self.status == VerificationStatus.SOURCE_HASH_MISMATCH:
                complete = all_actual
            else:
                complete = all_current_actual
            if not complete:
                raise ValueError(f"{self.status} requires the complete current actual matrix")
            self._validate_selected_mismatch()
        elif self.status == VerificationStatus.INVALID_MEDIA:
            if self.actual_media_sha256 is None or self.actual_size_bytes is None:
                raise ValueError("invalid media requires actual byte hash and size")
            undecodable = (
                self.actual_source_pixel_sha256,
                self.actual_output_pixel_sha256,
                self.actual_width,
                self.actual_height,
            )
            if any(value is not None for value in undecodable):
                raise ValueError("invalid media cannot claim decoded pixel or dimension facts")
        elif self.status == VerificationStatus.PRIVACY_POLICY_VIOLATION:
            if self.reason_code is None:
                raise ValueError("privacy-policy violation requires a typed reason code")
            if not (all_actual or no_actual):
                raise ValueError(
                    "privacy-policy violation requires either all or no actual media facts"
                )
        return self

    def _all_expected_values_match(self) -> bool:
        return (
            self.expected_source_pixel_sha256 == self.actual_source_pixel_sha256
            and self.expected_output_pixel_sha256 == self.actual_output_pixel_sha256
            and self.expected_media_sha256 == self.actual_media_sha256
            and self.expected_width == self.actual_width
            and self.expected_height == self.actual_height
            and self.expected_size_bytes == self.actual_size_bytes
        )

    def _all_expected_current_values_match(self) -> bool:
        return (
            self.expected_output_pixel_sha256 == self.actual_output_pixel_sha256
            and self.expected_media_sha256 == self.actual_media_sha256
            and self.expected_width == self.actual_width
            and self.expected_height == self.actual_height
            and self.expected_size_bytes == self.actual_size_bytes
        )

    def _validate_selected_mismatch(self) -> None:
        if (
            self.status == VerificationStatus.SOURCE_HASH_MISMATCH
            and self.expected_source_pixel_sha256 == self.actual_source_pixel_sha256
        ):
            raise ValueError("source hash mismatch requires different source pixel hashes")
        if (
            self.status == VerificationStatus.PIXEL_HASH_MISMATCH
            and self.expected_output_pixel_sha256 == self.actual_output_pixel_sha256
        ):
            raise ValueError("pixel hash mismatch requires different output pixel hashes")
        if (
            self.status == VerificationStatus.MEDIA_HASH_MISMATCH
            and self.expected_media_sha256 == self.actual_media_sha256
        ):
            raise ValueError("media hash mismatch requires different encoded media hashes")
        if self.status == VerificationStatus.SIZE_MISMATCH:
            if self.expected_size_bytes == self.actual_size_bytes:
                raise ValueError("size mismatch requires different encoded media sizes")
            non_size_values_match = (
                self.actual_source_pixel_sha256 in {None, self.expected_source_pixel_sha256}
                and self.expected_output_pixel_sha256 == self.actual_output_pixel_sha256
                and self.expected_media_sha256 == self.actual_media_sha256
                and self.expected_width == self.actual_width
                and self.expected_height == self.actual_height
            )
            if not non_size_values_match:
                raise ValueError("size mismatch permits only the encoded size to differ")
        if self.status == VerificationStatus.DIMENSION_MISMATCH and (
            self.expected_width == self.actual_width and self.expected_height == self.actual_height
        ):
            raise ValueError("dimension mismatch requires different dimensions")


class RetentionHold(FrozenContractModel):
    run_id: ReferenceToken
    hold_id: ReferenceToken
    target_ref: ScopedArtifactRef
    kind: RetentionHoldKind
    owner_ref: ScopedArtifactRef
    active: Literal[True] = True
    manifest_id: Sha256Hex
    policy_version: ReferenceToken
    reason_code: ReferenceToken | None = None

    @field_validator("run_id", "hold_id", "policy_version")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "retention hold reference")

    @model_validator(mode="after")
    def validate_scope_and_kinds(self) -> RetentionHold:
        if self.target_ref.run_id != self.run_id or self.owner_ref.run_id != self.run_id:
            raise ValueError("retention target and owner must belong to the hold run")
        if self.target_ref.ref.kind not in {ArtifactKind.CROP, ArtifactKind.MEDIA}:
            raise ValueError("retention holds can target only crop or media artifacts")
        allowed_owner_kinds = _RETENTION_OWNER_KINDS[self.kind]
        if self.owner_ref.ref.kind not in allowed_owner_kinds:
            expected = ", ".join(sorted(kind.value for kind in allowed_owner_kinds))
            raise ValueError(f"{self.kind} retention owner must be one of: {expected}")
        return self


class PurgeItemResult(FrozenContractModel):
    """Typed outcome for one content-addressed media retention decision."""

    run_id: ReferenceToken
    media_ref: ArtifactRef
    crop_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    disposition: PurgeDisposition
    reason_code: PurgeReasonCode
    previous_availability: MediaAvailability
    current_availability: MediaAvailability
    hold_kinds: tuple[RetentionHoldKind, ...] = ()
    audit_sequences: tuple[int, ...] = ()

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "purge result run_id")

    @model_validator(mode="after")
    def validate_outcome_matrix(self) -> PurgeItemResult:
        if self.media_ref.kind != ArtifactKind.MEDIA:
            raise ValueError("purge media_ref must identify media")
        if any(ref.kind != ArtifactKind.CROP for ref in self.crop_refs):
            raise ValueError("purge crop_refs must identify crops")
        crop_keys = tuple(ref.sort_key for ref in self.crop_refs)
        if len(crop_keys) != len(set(crop_keys)):
            raise ValueError("purge crop_refs must be unique")
        if crop_keys != tuple(sorted(crop_keys)):
            raise ValueError("purge crop_refs must use stable order")
        if len(self.hold_kinds) != len(set(self.hold_kinds)):
            raise ValueError("purge hold kinds must be unique")
        if self.hold_kinds != tuple(sorted(self.hold_kinds, key=lambda item: item.value)):
            raise ValueError("purge hold kinds must use stable order")
        if (
            len(self.audit_sequences) != len(set(self.audit_sequences))
            or self.audit_sequences != tuple(sorted(self.audit_sequences))
            or any(sequence < 0 for sequence in self.audit_sequences)
        ):
            raise ValueError("purge audit sequences must be unique non-negative stable order")

        if self.disposition == PurgeDisposition.PURGED:
            if (
                self.reason_code not in _PURGED_REASONS
                or self.current_availability != MediaAvailability.PURGED_BY_RETENTION
                or len(self.audit_sequences) != 2
                or self.hold_kinds
                or (
                    self.reason_code == PurgeReasonCode.EXPIRED_AND_PURGED
                    and self.previous_availability != MediaAvailability.AVAILABLE
                )
                or (
                    self.reason_code == PurgeReasonCode.RECOVERED_PURGE_COMPLETED
                    and self.previous_availability != MediaAvailability.PURGING
                )
            ):
                raise ValueError("purged outcome has an invalid reason, state, hold, or audit")
        elif self.disposition == PurgeDisposition.RECOVERY_REQUIRED:
            cleanup_failed = self.reason_code == PurgeReasonCode.TRASH_CLEANUP_FAILED
            if self.reason_code not in _RECOVERY_REASONS or self.hold_kinds:
                raise ValueError("recovery-required outcome has an invalid reason or hold")
            if cleanup_failed:
                if (
                    self.previous_availability != MediaAvailability.PURGED_BY_RETENTION
                    or self.current_availability != MediaAvailability.PURGED_BY_RETENTION
                    or len(self.audit_sequences) != 2
                ):
                    raise ValueError(
                        "trash-cleanup recovery must keep purged state and both purge audits"
                    )
            elif (
                self.previous_availability != MediaAvailability.PURGING
                or self.current_availability != MediaAvailability.PURGING
                or len(self.audit_sequences) != 1
            ):
                raise ValueError("purge recovery must remain in PURGING with its intent audit")
        else:
            if self.reason_code == PurgeReasonCode.ACTIVE_RETENTION_HOLD:
                if (
                    not self.hold_kinds
                    or self.previous_availability != MediaAvailability.AVAILABLE
                    or self.current_availability != MediaAvailability.AVAILABLE
                    or self.audit_sequences
                ):
                    raise ValueError(
                        "active-hold retention requires available media and hold kinds"
                    )
            elif self.reason_code == PurgeReasonCode.RETENTION_NOT_EXPIRED:
                if (
                    self.hold_kinds
                    or self.previous_availability != MediaAvailability.AVAILABLE
                    or self.current_availability != MediaAvailability.AVAILABLE
                    or self.audit_sequences
                ):
                    raise ValueError("unexpired retention requires unchanged available media")
            elif self.reason_code == PurgeReasonCode.ALREADY_PURGED:
                if (
                    self.hold_kinds
                    or self.previous_availability != MediaAvailability.PURGED_BY_RETENTION
                    or self.current_availability != MediaAvailability.PURGED_BY_RETENTION
                    or len(self.audit_sequences) != 2
                ):
                    raise ValueError("already-purged retention requires purged media state")
            else:
                raise ValueError("retained outcome uses an invalid reason code")
        return self


__all__ = [
    "CLOSURE_VALIDATOR_VERSION",
    "CONTENT_ADDRESSED_ARTIFACT_KINDS",
    "UUID_ARTIFACT_KINDS",
    "ArtifactRef",
    "ArtifactVerification",
    "ClosureDefect",
    "ClosureReport",
    "PurgeItemResult",
    "RetentionHold",
    "ScopedArtifactRef",
]
