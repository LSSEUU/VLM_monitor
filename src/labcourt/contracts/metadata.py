"""Safety checks for the few intentionally extensible scalar metadata maps."""

from __future__ import annotations

import re
from collections.abc import Mapping

from labcourt.contracts.base import Scalar

_SENSITIVE_KEY_PARTS = {
    "api_key",
    "credential",
    "cwd",
    "email",
    "face",
    "hostname",
    "id_card",
    "name",
    "password",
    "path",
    "phone",
    "reid",
    "secret",
    "token",
    "username",
}
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


def validate_safe_scalar_metadata(
    value: Mapping[str, Scalar],
    *,
    allowed_keys: set[str] | None = None,
) -> Mapping[str, Scalar]:
    if len(value) > 32:
        raise ValueError("metadata cannot contain more than 32 fields")
    for key, item in value.items():
        normalized_key = key.casefold()
        if not key or len(key) > 64 or any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
            raise ValueError(f"metadata key is forbidden: {key!r}")
        if allowed_keys is not None and key not in allowed_keys:
            raise ValueError(f"metadata key is not allowed here: {key!r}")
        if isinstance(item, str):
            if len(item) > 512:
                raise ValueError(f"metadata value is too long: {key!r}")
            if item.startswith(("/", "\\\\")) or _WINDOWS_ABSOLUTE.match(item):
                raise ValueError(f"metadata cannot contain an absolute path: {key!r}")
    return value
