"""Deterministic in-memory frame sources with optional local UTF-8 fixtures."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Self

from pydantic import TypeAdapter, ValidationError

from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.frames import FrameData, FrameRef
from labcourt.exceptions import ContractViolation, EvidenceMissing

_BUNDLE_ADAPTER = TypeAdapter(FrameBundle)
_BUNDLES_ADAPTER = TypeAdapter(tuple[FrameBundle, ...])


def _read_utf8(path: Path) -> str:
    raw_path = str(path)
    prefix = raw_path.split(":", maxsplit=1)[0]
    looks_like_uri = (
        ":" in raw_path
        and len(prefix) > 1
        and prefix.replace("+", "").replace("-", "").replace(".", "").isalnum()
    )
    if path.drive.startswith("\\\\") or raw_path.startswith(("\\\\", "//")) or looks_like_uri:
        raise ContractViolation("precomputed frame fixtures must use a local filesystem path")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ContractViolation("cannot read precomputed frame fixture as UTF-8") from None


def _require_range_argument(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    return value


class _InMemoryFrameSource:
    """Shared immutable index for FrameSource-compatible offline adapters."""

    __slots__ = ("_bundles", "_frame_data_by_id", "_ordered_frame_data")

    def __init__(self, bundles: Sequence[FrameBundle], *, namespace: str) -> None:
        by_id: dict[str, FrameBundle] = {}
        for bundle in bundles:
            if not isinstance(bundle, FrameBundle):
                raise TypeError("frame sources require validated FrameBundle values")
            frame_id = bundle.frame.frame_id
            if frame_id in by_id:
                raise ContractViolation(f"duplicate frame_id: {frame_id}")
            by_id[frame_id] = bundle

        self._bundles = tuple(
            sorted(
                by_id.values(),
                key=lambda bundle: (
                    bundle.frame.camera_id,
                    bundle.frame.stream_id,
                    bundle.frame.frame_index,
                ),
            )
        )
        self._ordered_frame_data = tuple(
            FrameData(
                frame=bundle.frame,
                media_ref=(
                    f"memory/{namespace}/{bundle.frame.camera_id}/"
                    f"{bundle.frame.stream_id}/{bundle.frame.frame_index}"
                ),
                ephemeral=True,
            )
            for bundle in self._bundles
        )
        self._frame_data_by_id = {
            frame_data.frame.frame_id: frame_data for frame_data in self._ordered_frame_data
        }

    def iter_frames(self) -> Iterator[FrameBundle]:
        return iter(self._bundles)

    def get_frame(self, frame_id: str) -> FrameData:
        try:
            return self._frame_data_by_id[frame_id]
        except KeyError:
            raise EvidenceMissing(f"unknown frame_id: {frame_id}") from None

    def get_range(
        self,
        camera_id: str,
        stream_id: str,
        start: int,
        end: int,
        step: int = 1,
    ) -> Sequence[FrameData]:
        start = _require_range_argument(start, "start")
        end = _require_range_argument(end, "end")
        step = _require_range_argument(step, "step")
        if start < 0 or end < start:
            raise ValueError("frame range must satisfy 0 <= start <= end")
        if step <= 0:
            raise ValueError("frame range step must be positive")
        return tuple(
            frame_data
            for frame_data in self._ordered_frame_data
            if frame_data.frame.camera_id == camera_id
            and frame_data.frame.stream_id == stream_id
            and start <= frame_data.frame.frame_index < end
            and (frame_data.frame.frame_index - start) % step == 0
        )


class SyntheticFrameSource(_InMemoryFrameSource):
    """Build empty, pixel-free FrameBundles from authoritative frame references."""

    def __init__(self, frames: Sequence[FrameRef]) -> None:
        bundles: list[FrameBundle] = []
        for frame in frames:
            if not isinstance(frame, FrameRef):
                raise TypeError("synthetic sources require validated FrameRef values")
            bundles.append(FrameBundle(frame=frame))
        super().__init__(bundles, namespace="synthetic")


class PrecomputedFrameSource(_InMemoryFrameSource):
    """Serve strictly validated, precomputed FrameBundles without network access."""

    def __init__(self, bundles: Sequence[FrameBundle]) -> None:
        super().__init__(bundles, namespace="precomputed")

    @classmethod
    def from_json_file(cls, path: Path) -> Self:
        """Load one strict JSON array using an explicit UTF-8 decoder."""

        try:
            bundles = _BUNDLES_ADAPTER.validate_json(_read_utf8(path))
        except ValidationError:
            raise ContractViolation(
                "precomputed frame fixture must be a JSON array of FrameBundle records"
            ) from None
        return cls(bundles)

    @classmethod
    def from_jsonl_file(cls, path: Path) -> Self:
        """Load one strict FrameBundle per non-empty UTF-8 JSONL line."""

        text = _read_utf8(path)
        if not text:
            return cls(())
        bundles: list[FrameBundle] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                raise ContractViolation(
                    f"precomputed frame JSONL contains an empty line at {line_number}"
                )
            try:
                bundles.append(_BUNDLE_ADAPTER.validate_json(line))
            except ValidationError:
                raise ContractViolation(
                    f"invalid FrameBundle JSON on precomputed line {line_number}"
                ) from None
        return cls(bundles)


__all__ = ["PrecomputedFrameSource", "SyntheticFrameSource"]
