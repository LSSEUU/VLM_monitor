from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_source_authority_sealing import (
    M6SourceAuthoritySealingError,
    M6SourceAuthoritySealingErrorCode,
    seal_m6_gate_current_closures,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureBasis
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.ports.m6_source_authority_sealing import (
    M6CurrentPackObservation,
    M6GateSourceObservation,
)
from tests.contract.test_m5_precedent_usage_contracts import _ready_case


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _case_sha256(value: object) -> str:
    return _sha(canonical_json(value.model_dump(mode="json")))  # type: ignore[attr-defined]


def _closure(pack: EvidencePack, *, input_sha256: str | None = None) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=input_sha256 or pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _verification(crop: Crop, *, pixel_sha256: str | None = None) -> ArtifactVerification:
    observed_pixel = pixel_sha256 or crop.pixel_sha256
    return ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=crop.media_type,
        expected_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=observed_pixel,
        actual_output_pixel_sha256=observed_pixel,
        expected_media_sha256=crop.media_sha256,
        actual_media_sha256=crop.media_sha256,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )


def _fixture() -> tuple[object, EvidencePack, M6GateSourceObservation]:
    case, _ = _ready_case(())
    review = case.procedural_reviews[0]
    pack = next(
        item
        for item in case.evidence_packs
        if (item.pack_id, item.version) == (review.evidence_pack_id, review.evidence_pack_version)
    )
    observation = M6GateSourceObservation(
        source_case=case,
        source_case_revision=7,
        source_case_document_sha256=_case_sha256(case),
        audit_head_sequence=12,
        audit_head_hash=_sha("audit-head"),
        packs=(
            M6CurrentPackObservation(
                pack=pack,
                current_closure=_closure(pack),
                crop_verifications=tuple(_verification(item) for item in pack.crops),
            ),
        ),
    )
    return case, pack, observation


def _assert_error(
    code: M6SourceAuthoritySealingErrorCode,
    observation: object,
) -> None:
    with pytest.raises(M6SourceAuthoritySealingError) as raised:
        seal_m6_gate_current_closures(observation=observation)
    assert raised.value.code == code


def test_seals_only_the_exact_atomic_source_observation() -> None:
    case, pack, observation = _fixture()

    sealed = seal_m6_gate_current_closures(observation=observation)

    assert sealed.source_case == case
    assert sealed.source_case_revision == 7
    assert sealed.audit_head_sequence == 12
    assert len(sealed.gate_current_closures) == 1
    receipt = sealed.gate_current_closures[0]
    assert receipt.basis == M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED
    assert receipt.current_closure == _closure(pack)
    assert tuple(item.artifact_ref.artifact_id for item in receipt.crop_verifications) == tuple(
        sorted(item.crop_id for item in pack.crops)
    )


def test_rejects_dynamic_case_that_differs_from_persisted_case_document() -> None:
    _, _, observation = _fixture()
    forged = M6GateSourceObservation(
        source_case=observation.source_case,
        source_case_revision=observation.source_case_revision,
        source_case_document_sha256=_sha("other-case-document"),
        audit_head_sequence=observation.audit_head_sequence,
        audit_head_hash=observation.audit_head_hash,
        packs=observation.packs,
    )

    _assert_error(M6SourceAuthoritySealingErrorCode.SOURCE_CASE_DOCUMENT_MISMATCH, forged)


def test_rejects_missing_or_extra_reviewed_pack_observations() -> None:
    _, _, observation = _fixture()
    missing = M6GateSourceObservation(
        source_case=observation.source_case,
        source_case_revision=observation.source_case_revision,
        source_case_document_sha256=observation.source_case_document_sha256,
        audit_head_sequence=observation.audit_head_sequence,
        audit_head_hash=observation.audit_head_hash,
        packs=(),
    )

    _assert_error(M6SourceAuthoritySealingErrorCode.REVIEW_PACK_COVERAGE_MISMATCH, missing)


def test_rejects_noncurrent_pack_closure() -> None:
    _, pack, observation = _fixture()
    stale_pack = M6CurrentPackObservation(
        pack=pack,
        current_closure=_closure(pack, input_sha256=_sha("stale-pack")),
        crop_verifications=observation.packs[0].crop_verifications,
    )
    stale = M6GateSourceObservation(
        source_case=observation.source_case,
        source_case_revision=observation.source_case_revision,
        source_case_document_sha256=observation.source_case_document_sha256,
        audit_head_sequence=observation.audit_head_sequence,
        audit_head_hash=observation.audit_head_hash,
        packs=(stale_pack,),
    )

    _assert_error(M6SourceAuthoritySealingErrorCode.CURRENT_CLOSURE_INVALID, stale)


def test_rejects_self_consistent_but_wrong_crop_observation() -> None:
    _, pack, observation = _fixture()
    wrong_pack = M6CurrentPackObservation(
        pack=pack,
        current_closure=_closure(pack),
        crop_verifications=tuple(
            _verification(item, pixel_sha256=_sha(f"wrong:{item.crop_id}")) for item in pack.crops
        ),
    )
    wrong = M6GateSourceObservation(
        source_case=observation.source_case,
        source_case_revision=observation.source_case_revision,
        source_case_document_sha256=observation.source_case_document_sha256,
        audit_head_sequence=observation.audit_head_sequence,
        audit_head_hash=observation.audit_head_hash,
        packs=(wrong_pack,),
    )

    _assert_error(M6SourceAuthoritySealingErrorCode.CURRENT_MEDIA_VERIFICATION_FAILED, wrong)


@pytest.mark.parametrize("bad_argument", [None, "observation", object()])
def test_rejects_untyped_observation(bad_argument: object) -> None:
    _assert_error(M6SourceAuthoritySealingErrorCode.INVALID_ARGUMENT, bad_argument)
