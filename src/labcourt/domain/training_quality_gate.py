"""Pure M5 gate separating reviewed training truth from quarantined labels."""

from __future__ import annotations

from labcourt.contracts.enums import TrainingLabelQuality


def training_label_is_exportable(
    *,
    quality: TrainingLabelQuality,
    excluded_reason: str | None,
) -> bool:
    """Allow only non-excluded human or appeal-confirmed labels into datasets."""

    if excluded_reason is not None:
        return False
    if quality == TrainingLabelQuality.HUMAN_CONFIRMED:
        return True
    return quality == TrainingLabelQuality.APPEAL_CONFIRMED


__all__ = ["training_label_is_exportable"]
