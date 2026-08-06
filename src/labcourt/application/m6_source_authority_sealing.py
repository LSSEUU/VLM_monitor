"""Validate one atomic source observation and seal its Gate receipts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_source_authority_sealing import (
    M6CurrentPackObservation,
    M6GateSourceObservation,
)


class M6SourceAuthoritySealingErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CASE_DOCUMENT_MISMATCH = "SOURCE_CASE_DOCUMENT_MISMATCH"
    REVIEW_PACK_COVERAGE_MISMATCH = "REVIEW_PACK_COVERAGE_MISMATCH"
    CURRENT_CLOSURE_INVALID = "CURRENT_CLOSURE_INVALID"
    CURRENT_MEDIA_VERIFICATION_FAILED = "CURRENT_MEDIA_VERIFICATION_FAILED"


class M6SourceAuthoritySealingError(LabCourtError):
    """An atomic source observation could not be sealed without guessing."""

    def __init__(self, code: M6SourceAuthoritySealingErrorCode) -> None:
        if not isinstance(code, M6SourceAuthoritySealingErrorCode):
            raise TypeError("code must be an M6SourceAuthoritySealingErrorCode")
        self.code = code
        super().__init__(f"M6 source authority sealing failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6SealedGateSource:
    """Source Case and receipts proven by one atomic repository observation."""

    source_case: Case
    source_case_revision: int
    source_case_document_sha256: str
    audit_head_sequence: int
    audit_head_hash: str
    gate_current_closures: tuple[M6GateCurrentClosureReceipt, ...]


def _fail(code: M6SourceAuthoritySealingErrorCode) -> NoReturn:
    raise M6SourceAuthoritySealingError(code)


def _canonical_case(value: Case) -> Case:
    try:
        controlled = Case.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT)
    return controlled


def _document_sha256(value: object) -> str:
    try:
        document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        _fail(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT)
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _expected_current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _verification_matches_crop(
    verification: ArtifactVerification,
    crop: Crop,
) -> bool:
    return (
        verification.artifact_ref == ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        and verification.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
        and verification.availability == MediaAvailability.AVAILABLE
        and verification.media_type == crop.media_type
        and verification.expected_source_pixel_sha256 == crop.source_media_sha256
        and verification.actual_source_pixel_sha256 is None
        and verification.expected_output_pixel_sha256 == crop.pixel_sha256
        and verification.actual_output_pixel_sha256 == crop.pixel_sha256
        and verification.expected_media_sha256 == crop.media_sha256
        and verification.actual_media_sha256 == crop.media_sha256
        and verification.expected_width == crop.output_width
        and verification.actual_width == crop.output_width
        and verification.expected_height == crop.output_height
        and verification.actual_height == crop.output_height
        and verification.expected_size_bytes == crop.size_bytes
        and verification.actual_size_bytes == crop.size_bytes
        and verification.reason_code is None
    )


def _seal_pack_observation(
    observation: M6CurrentPackObservation,
    *,
    review: ProceduralReview,
) -> M6GateCurrentClosureReceipt:
    pack = observation.pack
    if observation.current_closure != _expected_current_closure(pack):
        _fail(M6SourceAuthoritySealingErrorCode.CURRENT_CLOSURE_INVALID)
    crops = {item.crop_id: item for item in pack.crops}
    verifications = {item.artifact_ref.artifact_id: item for item in observation.crop_verifications}
    if len(verifications) != len(observation.crop_verifications) or set(verifications) != set(
        crops
    ):
        _fail(M6SourceAuthoritySealingErrorCode.CURRENT_MEDIA_VERIFICATION_FAILED)
    if any(
        crop.availability != MediaAvailability.AVAILABLE
        or not _verification_matches_crop(verifications[crop_id], crop)
        for crop_id, crop in crops.items()
    ):
        _fail(M6SourceAuthoritySealingErrorCode.CURRENT_MEDIA_VERIFICATION_FAILED)
    basis = (
        M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED
        if crops
        else M6GateCurrentClosureBasis.SEMANTIC_ONLY_NO_CROPS
    )
    try:
        return M6GateCurrentClosureReceipt(
            run_id=pack.run_id,
            case_id=pack.case_id,
            manifest_id=pack.manifest_id,
            review_version=review.version,
            source_review_id=review.review_id,
            source_review_document_sha256=_document_sha256(review),
            evidence_pack_id=pack.pack_id,
            evidence_pack_version=pack.version,
            evidence_pack_document_sha256=_document_sha256(pack),
            basis=basis,
            current_closure=observation.current_closure,
            crop_verifications=tuple(
                sorted(
                    observation.crop_verifications,
                    key=lambda item: item.artifact_ref.sort_key,
                )
            ),
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT)


def seal_m6_gate_current_closures(*, observation: object) -> M6SealedGateSource:
    """Seal receipts from one transaction-scoped repository observation."""

    if not isinstance(observation, M6GateSourceObservation):
        _fail(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT)
    case = _canonical_case(observation.source_case)
    if _document_sha256(case) != observation.source_case_document_sha256:
        _fail(M6SourceAuthoritySealingErrorCode.SOURCE_CASE_DOCUMENT_MISMATCH)

    pack_observations = {(item.pack.pack_id, item.pack.version): item for item in observation.packs}
    if len(pack_observations) != len(observation.packs):
        _fail(M6SourceAuthoritySealingErrorCode.REVIEW_PACK_COVERAGE_MISMATCH)
    expected_keys = {
        (item.evidence_pack_id, item.evidence_pack_version) for item in case.procedural_reviews
    }
    case_packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
    if set(pack_observations) != expected_keys or any(
        case_packs.get(key) != item.pack for key, item in pack_observations.items()
    ):
        _fail(M6SourceAuthoritySealingErrorCode.REVIEW_PACK_COVERAGE_MISMATCH)

    receipts = tuple(
        _seal_pack_observation(
            pack_observations[(review.evidence_pack_id, review.evidence_pack_version)],
            review=review,
        )
        for review in sorted(
            case.procedural_reviews,
            key=lambda item: (item.version, item.review_id),
        )
    )
    return M6SealedGateSource(
        source_case=case,
        source_case_revision=observation.source_case_revision,
        source_case_document_sha256=observation.source_case_document_sha256,
        audit_head_sequence=observation.audit_head_sequence,
        audit_head_hash=observation.audit_head_hash,
        gate_current_closures=receipts,
    )


__all__ = [
    "M6SealedGateSource",
    "M6SourceAuthoritySealingError",
    "M6SourceAuthoritySealingErrorCode",
    "seal_m6_gate_current_closures",
]
