"""Embedding port without a NumPy dependency in core contracts."""

from collections.abc import Sequence
from typing import Protocol

from labcourt.contracts.evidence import Crop

EmbeddingVector = tuple[float, ...]


class EmbeddingClient(Protocol):
    def embed_text(self, texts: Sequence[str]) -> Sequence[EmbeddingVector]: ...

    def embed_images(self, crops: Sequence[Crop]) -> Sequence[EmbeddingVector]: ...
