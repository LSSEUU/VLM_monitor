"""Observability scoring for evidence ranking, never trigger gating."""

from __future__ import annotations

from math import fsum

from labcourt.contracts.config import ObservabilityWeights
from labcourt.contracts.enums import ObservationSource
from labcourt.contracts.evidence import ObservabilityComponents, ObservabilityScore


def score_observability(
    components: ObservabilityComponents,
    weights: ObservabilityWeights,
    *,
    source: ObservationSource,
) -> ObservabilityScore:
    """Apply the six configured weights and retain every component and its source.

    ``source`` is mandatory so precomputed fixtures cannot masquerade as pixel-derived
    measurements. This function deliberately accepts no clear-frame threshold and emits
    no gate decision; callers may use the score only for frame selection and sufficiency.
    """

    total = fsum(
        (
            weights.person_confidence * components.person_confidence,
            weights.keypoint_visibility * components.keypoint_visibility,
            weights.frontality * components.frontality,
            weights.sharpness * components.sharpness,
            weights.exposure * components.exposure,
            weights.non_occlusion * components.non_occlusion,
        )
    )
    # Validated inputs keep this in [0, 1]; clamping absorbs only binary rounding at an
    # endpoint (for example 1.0000000000000002), not a configuration error.
    total = min(1.0, max(0.0, total))
    return ObservabilityScore(total=total, components=components, source=source)
