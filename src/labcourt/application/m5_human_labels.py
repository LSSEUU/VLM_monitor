"""Bind concise human label inputs to immutable appeal review authority."""

from __future__ import annotations

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality
from labcourt.contracts.m5_appeals import (
    MAX_M5_APPEAL_TRAINING_LABELS,
    AppealVersionAuthority,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.training import TrainingLabel
from labcourt.exceptions import ContractViolation


def build_m5_appeal_training_labels(
    *,
    appeal_authority: AppealVersionAuthority,
    terminal_status: AppealStatus,
    authored_inputs: tuple[M5AppealTrainingLabelInput, ...],
) -> tuple[TrainingLabel, ...]:
    """Create stable labels without asking a reviewer to author manifest boilerplate."""

    if not isinstance(appeal_authority, AppealVersionAuthority):
        raise TypeError("appeal_authority must be an AppealVersionAuthority")
    if not isinstance(authored_inputs, tuple) or any(
        not isinstance(item, M5AppealTrainingLabelInput) for item in authored_inputs
    ):
        raise TypeError("authored_inputs must be a tuple of M5AppealTrainingLabelInput")
    if len(authored_inputs) > MAX_M5_APPEAL_TRAINING_LABELS:
        raise ContractViolation(
            "appeal label inputs exceed the immutable resolution contract limit"
        )
    if (
        appeal_authority.version != 2
        or appeal_authority.appeal.status != AppealStatus.UNDER_REVIEW
        or appeal_authority.assigned_reviewer_id is None
    ):
        raise ContractViolation("appeal labels require the current UNDER_REVIEW authority")
    if terminal_status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}:
        raise ContractViolation("appeal labels require a terminal resolution status")
    input_ids = tuple(item.input_id for item in authored_inputs)
    if len(input_ids) != len(set(input_ids)):
        raise ContractViolation("appeal label inputs contain duplicate human facts")

    quality = (
        TrainingLabelQuality.APPEAL_CONFIRMED
        if terminal_status == AppealStatus.OVERTURNED
        else TrainingLabelQuality.HUMAN_CONFIRMED
    )
    reviewer_id = appeal_authority.assigned_reviewer_id
    appeal_id = appeal_authority.appeal.appeal_id
    labels = tuple(
        TrainingLabel(
            label_id=sha256_hex(
                [
                    "m5-appeal-training-label",
                    1,
                    appeal_authority.authority_sha256,
                    terminal_status,
                    reviewer_id,
                    authored.input_id,
                ]
            ),
            case_id=appeal_authority.appeal.case_id,
            crop_id=authored.crop_id,
            bbox=authored.bbox,
            label_name=authored.label_name,
            label_value=authored.label_value,
            quality=quality,
            source=f"appeal-review:{appeal_id}",
            reviewer_id=reviewer_id,
            rule_version=appeal_authority.rule_version,
            detector_manifest_id=appeal_authority.source_case_authority.detector_manifest_id,
        )
        for authored in authored_inputs
    )
    return tuple(sorted(labels, key=lambda item: item.label_id))


__all__ = ["build_m5_appeal_training_labels"]
