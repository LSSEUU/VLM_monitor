# mypy: disable-error-code="override"
"""Deeply immutable mapping helpers for frozen wire contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import NoReturn


class FrozenDict(dict[object, object]):
    """A JSON-serializable dict subclass that rejects every mutation API."""

    @staticmethod
    def _immutable() -> NoReturn:
        raise TypeError("contract mappings are immutable")

    def __setitem__(self, key: object, value: object) -> None:
        self._immutable()

    def __delitem__(self, key: object) -> None:
        self._immutable()

    def clear(self) -> None:
        self._immutable()

    def pop(self, *args: object, **kwargs: object) -> object:
        self._immutable()

    def popitem(self) -> tuple[object, object]:
        self._immutable()

    def setdefault(self, key: object, default: object = None) -> object:
        self._immutable()

    def update(self, *args: object, **kwargs: object) -> None:
        self._immutable()

    def __ior__(self, other: object) -> FrozenDict:  # type: ignore[misc]
        self._immutable()

    def __copy__(self) -> FrozenDict:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> FrozenDict:
        return self


def deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return FrozenDict({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(deep_freeze(item) for item in value)
    return value
