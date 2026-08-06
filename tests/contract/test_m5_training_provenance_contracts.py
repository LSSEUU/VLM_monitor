from __future__ import annotations

import pytest
from pydantic import ValidationError

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.contracts.training import TrainingLabel

RUN_ID = "run-1"
CASE_ID = "case-1"
APPEAL_ID = "appeal-1"
REVIEWER_ID = "reviewer-1"
REVIEW_AUTHORITY_SHA256 = "a" * 64
TERMINAL_AUTHORITY_SHA256 = "b" * 64
RESOLUTION_INTENT_ID = "c" * 64
RESOLUTION_DOCUMENT_SHA256 = "d" * 64
RESOLUTION_EFFECT_ROOT_SHA256 = "e" * 64
MANIFEST_ID = "1" * 64
DETECTOR_MANIFEST_ID = "2" * 64
RULE_VERSION = "laboratory-v1"


def _quality(status: AppealStatus) -> TrainingLabelQuality:
    return (
        TrainingLabelQuality.APPEAL_CONFIRMED
        if status == AppealStatus.OVERTURNED
        else TrainingLabelQuality.HUMAN_CONFIRMED
    )


def _authority(
    status: AppealStatus = AppealStatus.UPHELD,
) -> M5TrainingLabelAuthority:
    authored = M5AppealTrainingLabelInput(
        crop_id="3" * 64,
        bbox=BBoxXYXY(x1=1, y1=2, x2=11, y2=12),
        label_name="reagent_container_closed",
        label_value=True,
    )
    quality = _quality(status)
    label_id = sha256_hex(
        [
            "m5-appeal-training-label",
            1,
            REVIEW_AUTHORITY_SHA256,
            status,
            REVIEWER_ID,
            authored.input_id,
        ]
    )
    label = TrainingLabel(
        label_id=label_id,
        case_id=CASE_ID,
        crop_id=authored.crop_id,
        bbox=authored.bbox,
        label_name=authored.label_name,
        label_value=authored.label_value,
        quality=quality,
        source=f"appeal-review:{APPEAL_ID}",
        reviewer_id=REVIEWER_ID,
        rule_version=RULE_VERSION,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
    )
    commit_receipt_id = sha256_hex(
        [
            "m5-appeal-resolution-commit-receipt",
            1,
            RESOLUTION_EFFECT_ROOT_SHA256,
        ]
    )
    provenance = M5StrongTrainingLabelProvenanceReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        appeal_id=APPEAL_ID,
        label_id=label.label_id,
        label_document_sha256=sha256_hex(label.model_dump(mode="json")),
        crop_id=label.crop_id,
        reviewer_id=REVIEWER_ID,
        quality=quality,
        authored_input=authored,
        review_authority_sha256=REVIEW_AUTHORITY_SHA256,
        terminal_authority_sha256=TERMINAL_AUTHORITY_SHA256,
        terminal_status=status,
        resolution_intent_id=RESOLUTION_INTENT_ID,
        resolution_document_sha256=RESOLUTION_DOCUMENT_SHA256,
        resolution_commit_receipt_id=commit_receipt_id,
        resolution_commit_effect_root_sha256=RESOLUTION_EFFECT_ROOT_SHA256,
        manifest_id=MANIFEST_ID,
        rule_version=RULE_VERSION,
        detector_manifest_id=DETECTOR_MANIFEST_ID,
    )
    return M5TrainingLabelAuthority(label=label, strong_provenance=provenance)


@pytest.mark.parametrize("status", [AppealStatus.UPHELD, AppealStatus.OVERTURNED])
def test_strong_training_authority_accepts_the_terminal_outcome_quality_matrix(
    status: AppealStatus,
) -> None:
    authority = _authority(status)
    provenance = authority.strong_provenance
    assert provenance is not None
    serialized = authority.model_dump(mode="json")

    assert M5TrainingLabelAuthority.model_validate(serialized) == authority
    assert provenance.quality == _quality(status)
    assert authority.label_document_sha256 == sha256_hex(authority.label.model_dump(mode="json"))
    assert len(provenance.provenance_id) == len(authority.authority_sha256) == 64


def test_strong_provenance_rejects_forged_computed_and_derived_roots() -> None:
    provenance = _authority().strong_provenance
    assert provenance is not None
    serialized = provenance.model_dump(mode="json")

    attacked = dict(serialized)
    attacked["provenance_id"] = "f" * 64
    with pytest.raises(ValidationError, match="provenance_id"):
        M5StrongTrainingLabelProvenanceReceipt.model_validate(attacked)
    with pytest.raises(ValidationError, match="human review authority"):
        provenance.model_copy(update={"review_authority_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="commit receipt ID"):
        provenance.model_copy(update={"resolution_commit_receipt_id": "f" * 64})
    with pytest.raises(ValidationError, match="commit receipt ID"):
        provenance.model_copy(update={"resolution_commit_effect_root_sha256": "f" * 64})


def test_strong_provenance_rejects_missing_required_roots_and_wrong_quality() -> None:
    provenance = _authority().strong_provenance
    assert provenance is not None
    payload = provenance.model_dump(
        mode="json",
        exclude={"provenance_id", "resolution_commit_receipt_id"},
    )

    with pytest.raises(ValidationError) as missing:
        M5StrongTrainingLabelProvenanceReceipt.model_validate(payload)
    assert any(
        error["loc"] == ("resolution_commit_receipt_id",) for error in missing.value.errors()
    )
    with pytest.raises(ValidationError, match="terminal Appeal outcome"):
        provenance.model_copy(update={"quality": TrainingLabelQuality.APPEAL_CONFIRMED})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("case_id", "case-2"),
        ("crop_id", "4" * 64),
        ("reviewer_id", "reviewer-2"),
        ("source", "appeal-review:appeal-2"),
        ("rule_version", "laboratory-v2"),
        ("detector_manifest_id", "5" * 64),
        ("excluded_reason", "quarantined"),
    ],
)
def test_training_label_authority_rejects_cross_scope_or_document_forgery(
    field: str,
    value: str,
) -> None:
    authority = _authority()
    attacked_label = authority.label.model_copy(update={field: value})

    with pytest.raises(ValidationError, match="conflicts with its strong provenance"):
        M5TrainingLabelAuthority(
            label=attacked_label,
            strong_provenance=authority.strong_provenance,
        )


def test_training_label_authority_rejects_forged_label_hash_and_computed_claims() -> None:
    authority = _authority()
    provenance = authority.strong_provenance
    assert provenance is not None

    forged_provenance = provenance.model_copy(update={"label_document_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="conflicts with its strong provenance"):
        M5TrainingLabelAuthority(
            label=authority.label,
            strong_provenance=forged_provenance,
        )

    serialized = authority.model_dump(mode="json")
    for claim in ("label_document_sha256", "authority_sha256"):
        attacked = dict(serialized)
        attacked[claim] = "f" * 64
        with pytest.raises(ValidationError, match=claim):
            M5TrainingLabelAuthority.model_validate(attacked)


@pytest.mark.parametrize(
    "quality",
    [TrainingLabelQuality.WEAK_AUTO, TrainingLabelQuality.CONSENSUS_REVIEWED],
)
def test_weak_training_labels_cannot_masquerade_with_strong_provenance(
    quality: TrainingLabelQuality,
) -> None:
    strong = _authority()
    weak_label = strong.label.model_copy(
        update={
            "quality": quality,
            "source": "automatic-weak-label",
            "reviewer_id": None,
        }
    )

    weak = M5TrainingLabelAuthority(label=weak_label)
    assert weak.strong_provenance is None
    with pytest.raises(ValidationError, match="weak training labels"):
        M5TrainingLabelAuthority(
            label=weak_label,
            strong_provenance=strong.strong_provenance,
        )


@pytest.mark.parametrize(
    "quality",
    [TrainingLabelQuality.HUMAN_CONFIRMED, TrainingLabelQuality.APPEAL_CONFIRMED],
)
def test_strong_training_labels_cannot_bypass_the_provenance_receipt(
    quality: TrainingLabelQuality,
) -> None:
    label = _authority().label.model_copy(update={"quality": quality})

    with pytest.raises(ValidationError, match="require closed strong provenance"):
        M5TrainingLabelAuthority(label=label)
