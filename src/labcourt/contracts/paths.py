"""Portable workspace-relative path validation."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "CLOCK$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    *(f"COM{index}" for index in "¹²³"),
    *(f"LPT{index}" for index in "¹²³"),
}
_WINDOWS_INVALID_CHARS = set('<>:"\\|?*')
SAFE_RELATIVE_PATH_PATTERN = (
    r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))"
    r"(?!.*[\\<>:\"|?*])(?:[^/\x00-\x1f]+/)*[^/\x00-\x1f]+$"
)


def require_safe_relative_posix_path(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("path must be a string")
    if not value or "\\" in value or _WINDOWS_DRIVE.match(value):
        raise ValueError("path must be a non-empty workspace-relative POSIX path")
    path = PurePosixPath(value)
    components = path.parts
    if (
        path.is_absolute()
        or value.startswith("//")
        or path.as_posix() != value
        or ".." in components
        or any(any(char in _WINDOWS_INVALID_CHARS for char in part) for part in components)
        or any(part.endswith((" ", ".")) for part in components)
        or any(part.split(".", maxsplit=1)[0].upper() in _WINDOWS_RESERVED for part in components)
        or any(ord(char) < 32 for char in value)
        or str(path) in {"", "."}
    ):
        raise ValueError("path must be a safe workspace-relative POSIX path")
    return value
