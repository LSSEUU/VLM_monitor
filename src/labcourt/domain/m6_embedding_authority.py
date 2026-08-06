"""Pure resolved M5 embedding authority used by locked M6 replay."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_precedents import M5EmbeddingChannel, M5EmbeddingVector
from labcourt.contracts.m6_replay_locked import (
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingScope,
)

_SCOPE_RANK = {
    M6LockedEmbeddingScope.QUERY: 0,
    M6LockedEmbeddingScope.PRECEDENT: 1,
}
_CHANNEL_RANK = {
    M6LockedEmbeddingChannel.TEXT: 0,
    M6LockedEmbeddingChannel.VISUAL: 1,
}


@dataclass(frozen=True, slots=True)
class M6ResolvedEmbeddingAuthority:
    """One canonical vector whose operational reference has been resolved."""

    scope: M6LockedEmbeddingScope
    channel: M6LockedEmbeddingChannel
    vector: M5EmbeddingVector
    document_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.scope, M6LockedEmbeddingScope) or not isinstance(
            self.channel,
            M6LockedEmbeddingChannel,
        ):
            raise TypeError("M6 resolved embedding scope and channel must be typed")
        if not isinstance(self.vector, M5EmbeddingVector):
            raise TypeError("M6 resolved embedding vector must be typed")
        try:
            canonical = M5EmbeddingVector.model_validate(
                self.vector.model_dump(mode="json", exclude_computed_fields=True)
            )
        except (TypeError, ValueError):
            raise ValueError("M6 resolved embedding vector is invalid") from None
        expected_channel = {
            M6LockedEmbeddingChannel.TEXT: M5EmbeddingChannel.TEXT,
            M6LockedEmbeddingChannel.VISUAL: M5EmbeddingChannel.VISUAL,
        }[self.channel]
        if canonical.request.channel != expected_channel:
            raise ValueError("M6 resolved embedding channel conflicts with its vector")
        document = canonical_json(canonical.model_dump(mode="json"))
        observed_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
        if observed_sha256 != self.document_sha256:
            raise ValueError("M6 resolved embedding document hash is invalid")
        object.__setattr__(self, "vector", canonical)

    @property
    def embedding_id(self) -> str:
        return self.vector.embedding_id

    @property
    def request_id(self) -> str:
        return self.vector.request.request_id

    @property
    def model_manifest_id(self) -> str:
        return self.vector.request.model_manifest_id

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return _SCOPE_RANK[self.scope], _CHANNEL_RANK[self.channel], self.embedding_id


__all__ = ["M6ResolvedEmbeddingAuthority"]
