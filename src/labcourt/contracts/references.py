"""Anonymous, camera-scoped reference token validation."""

from __future__ import annotations

import re
from typing import Annotated, TypeAlias

from pydantic import Field

REFERENCE_TOKEN_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
TRACK_REF_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
)
FRAME_ID_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:"
    r"(?:0|[1-9][0-9]{0,19})$"
)
ReferenceToken: TypeAlias = Annotated[str, Field(pattern=REFERENCE_TOKEN_PATTERN)]
TrackRef: TypeAlias = Annotated[str, Field(pattern=TRACK_REF_PATTERN)]
FrameId: TypeAlias = Annotated[str, Field(pattern=FRAME_ID_PATTERN)]

_REFERENCE_TOKEN = re.compile(REFERENCE_TOKEN_PATTERN)
_WINDOWS_DEVICE_BASENAMES = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


def require_reference_token(value: str, name: str) -> str:
    if not _REFERENCE_TOKEN.fullmatch(value):
        raise ValueError(f"{name} must be a 1-64 character anonymous ASCII reference token")
    return value


def require_portable_run_id(value: str, name: str) -> str:
    """Require one run directory segment with stable Windows/POSIX identity.

    Reference tokens are ASCII, but Windows additionally strips trailing dots
    and reserves device basenames even when an extension is present.  Runs are
    filesystem roots, so accepting either form would make distinct SQLite
    identities alias the same directory on a supported platform.
    """

    controlled = require_reference_token(value, name)
    basename = controlled.split(".", 1)[0].upper()
    if controlled.endswith(".") or basename in _WINDOWS_DEVICE_BASENAMES:
        raise ValueError(f"{name} must be a portable run filesystem identity")
    return controlled


def parse_track_ref(value: str) -> tuple[str, str, str]:
    """Parse the camera-scoped tracker identity used on public contracts."""

    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError("track_ref must be camera_id:tracker_epoch:local_track_id")
    for name, part in zip(
        ("camera_id", "tracker_epoch", "local_track_id"),
        parts,
        strict=True,
    ):
        require_reference_token(part, name)
    return parts[0], parts[1], parts[2]


def require_track_ref_camera(value: str, camera_id: str) -> str:
    track_camera, _, _ = parse_track_ref(value)
    if track_camera != camera_id:
        raise ValueError("track_ref belongs to another camera")
    return value


def parse_frame_id(value: str) -> tuple[str, str, int]:
    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError("frame_id must be camera_id:stream_id:frame_index")
    camera_id = require_reference_token(parts[0], "camera_id")
    stream_id = require_reference_token(parts[1], "stream_id")
    if (
        not parts[2].isascii()
        or not parts[2].isdigit()
        or (parts[2] != "0" and parts[2].startswith("0"))
        or len(parts[2]) > 20
    ):
        raise ValueError("frame_id frame_index must be a non-negative decimal integer")
    return camera_id, stream_id, int(parts[2])
