"""Offline adapters used by the deterministic core."""

from labcourt.adapters.in_memory_raw_cache import InMemoryRawFrameCache
from labcourt.adapters.precomputed import PrecomputedFrameSource, SyntheticFrameSource
from labcourt.adapters.stored_png_verifier import StoredPngVerifier

__all__ = [
    "InMemoryRawFrameCache",
    "PrecomputedFrameSource",
    "StoredPngVerifier",
    "SyntheticFrameSource",
]
