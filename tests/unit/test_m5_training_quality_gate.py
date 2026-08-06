from __future__ import annotations

import pytest

from labcourt.contracts.enums import TrainingLabelQuality
from labcourt.domain.training_quality_gate import training_label_is_exportable


@pytest.mark.parametrize(
    ("quality", "excluded_reason", "expected"),
    [
        (TrainingLabelQuality.HUMAN_CONFIRMED, "privacy-hold", False),
        (TrainingLabelQuality.HUMAN_CONFIRMED, None, True),
        (TrainingLabelQuality.APPEAL_CONFIRMED, None, True),
        (TrainingLabelQuality.WEAK_AUTO, None, False),
        (TrainingLabelQuality.CONSENSUS_REVIEWED, None, False),
    ],
)
def test_training_quality_gate_covers_all_trust_branches(
    quality: TrainingLabelQuality,
    excluded_reason: str | None,
    expected: bool,
) -> None:
    assert (
        training_label_is_exportable(quality=quality, excluded_reason=excluded_reason) is expected
    )
