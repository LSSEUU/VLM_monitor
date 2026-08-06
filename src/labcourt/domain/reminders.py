"""In-memory L0 reminder cooldown with no persistence capability."""

from __future__ import annotations

import hmac
import secrets

from labcourt.contracts.enums import PpeType
from labcourt.contracts.references import parse_track_ref, require_reference_token
from labcourt.contracts.reminders import SoftReminder, reminder_message_for

_ReminderKey = tuple[str, PpeType, str, str]


def _require_frame_index(frame_index: int) -> int:
    if not isinstance(frame_index, int) or isinstance(frame_index, bool):
        raise TypeError("frame_index must be an integer")
    if frame_index < 0:
        raise ValueError("frame_index must be non-negative")
    return frame_index


class InMemorySoftReminderService:
    """Emit controlled reminders while retaining cooldown state only in RAM."""

    __slots__ = ("_cooldown_frames", "_key_secret", "_last_observed", "_last_reminded")

    def __init__(self, cooldown_frames: int) -> None:
        cooldown_frames = _require_frame_index(cooldown_frames)
        if cooldown_frames == 0:
            raise ValueError("cooldown_frames must be positive")
        self._cooldown_frames = cooldown_frames
        self._key_secret = secrets.token_bytes(32)
        self._last_observed: dict[_ReminderKey, int] = {}
        self._last_reminded: dict[_ReminderKey, int] = {}

    @property
    def cooldown_frames(self) -> int:
        return self._cooldown_frames

    def maybe_remind(
        self,
        *,
        frame_index: int,
        track_ref: str,
        zone_id: str,
        ppe_type: PpeType,
        channel: str,
    ) -> SoftReminder | None:
        """Return an anonymous reminder unless this track is still cooling down."""

        frame_index = _require_frame_index(frame_index)
        parse_track_ref(track_ref)
        require_reference_token(zone_id, "zone_id")
        require_reference_token(channel, "channel")
        if not isinstance(ppe_type, PpeType):
            raise TypeError("ppe_type must be a PpeType")

        ephemeral_track_key = hmac.digest(
            self._key_secret,
            track_ref.encode("utf-8"),
            "sha256",
        ).hex()
        key = (ephemeral_track_key, ppe_type, zone_id, channel)
        last_observed = self._last_observed.get(key)
        if last_observed is not None and frame_index < last_observed:
            raise ValueError("reminder frames must be observed in non-decreasing order")
        self._last_observed[key] = frame_index

        last_reminded = self._last_reminded.get(key)
        if last_reminded is not None and frame_index - last_reminded < self._cooldown_frames:
            return None

        self._last_reminded[key] = frame_index
        return SoftReminder(
            zone_id=zone_id,
            ppe_type=ppe_type,
            message=reminder_message_for(ppe_type),
            channel=channel,
        )

    def prune(self, *, current_frame: int) -> int:
        """Forget expired ephemeral keys so long-running streams stay bounded."""

        current_frame = _require_frame_index(current_frame)
        stale = [
            key
            for key, last_observed in self._last_observed.items()
            if current_frame - last_observed >= self._cooldown_frames
        ]
        for key in stale:
            self._last_observed.pop(key, None)
            self._last_reminded.pop(key, None)
        return len(stale)


__all__ = ["InMemorySoftReminderService"]
