"""Pure-Python exact cosine and missing-channel fusion for M5 precedents."""

from __future__ import annotations

from dataclasses import dataclass
from math import fsum, isfinite, sqrt

from labcourt.contracts.m5_precedents import M5EmbeddingVector


@dataclass(frozen=True, slots=True)
class FusedPrecedentSimilarity:
    text_similarity: float | None
    visual_similarity: float | None
    normalized_text_weight: float
    normalized_visual_weight: float
    base_similarity: float


def exact_cosine(left: M5EmbeddingVector, right: M5EmbeddingVector) -> float:
    """Return deterministic exact cosine without optional numerical dependencies."""

    if left.request.channel != right.request.channel:
        raise ValueError("cosine channels must match")
    if left.request.model_manifest_id != right.request.model_manifest_id:
        raise ValueError("cosine embeddings must use the same model manifest")
    if len(left.values) != len(right.values):
        raise ValueError("cosine vector dimensions must match")
    numerator = fsum(a * b for a, b in zip(left.values, right.values, strict=True))
    left_norm = sqrt(fsum(value * value for value in left.values))
    right_norm = sqrt(fsum(value * value for value in right.values))
    if left_norm == 0.0 or right_norm == 0.0:
        raise ValueError("cosine vectors must have non-zero norms")
    score = numerator / (left_norm * right_norm)
    if not isfinite(score):
        raise ValueError("cosine result must be finite")
    return min(1.0, max(-1.0, score))


def maximum_pairwise_cosine(
    left: tuple[M5EmbeddingVector, ...],
    right: tuple[M5EmbeddingVector, ...],
) -> float | None:
    """Use the strongest exact visual match, with deterministic pair iteration."""

    if not left or not right:
        return None
    return max(exact_cosine(first, second) for first in left for second in right)


def fuse_available_channels(
    *,
    text_similarity: float | None,
    visual_similarity: float | None,
    text_weight: float,
    visual_weight: float,
) -> FusedPrecedentSimilarity | None:
    """Renormalize configured weights across shared channels, never against absence."""

    available_text_weight = text_weight if text_similarity is not None else 0.0
    available_visual_weight = visual_weight if visual_similarity is not None else 0.0
    total = available_text_weight + available_visual_weight
    if total == 0.0:
        return None
    normalized_text = available_text_weight / total
    normalized_visual = available_visual_weight / total
    base = normalized_text * (text_similarity or 0.0) + normalized_visual * (
        visual_similarity or 0.0
    )
    return FusedPrecedentSimilarity(
        text_similarity=text_similarity,
        visual_similarity=visual_similarity,
        normalized_text_weight=normalized_text,
        normalized_visual_weight=normalized_visual,
        base_similarity=min(1.0, max(-1.0, base)),
    )


def compare_precedent_embeddings(
    *,
    left_text: M5EmbeddingVector | None,
    left_visual: tuple[M5EmbeddingVector, ...],
    right_text: M5EmbeddingVector | None,
    right_visual: tuple[M5EmbeddingVector, ...],
    text_weight: float,
    visual_weight: float,
) -> FusedPrecedentSimilarity | None:
    text_similarity = (
        exact_cosine(left_text, right_text)
        if left_text is not None and right_text is not None
        else None
    )
    visual_similarity = maximum_pairwise_cosine(left_visual, right_visual)
    return fuse_available_channels(
        text_similarity=text_similarity,
        visual_similarity=visual_similarity,
        text_weight=text_weight,
        visual_weight=visual_weight,
    )


__all__ = [
    "FusedPrecedentSimilarity",
    "compare_precedent_embeddings",
    "exact_cosine",
    "fuse_available_channels",
    "maximum_pairwise_cosine",
]
