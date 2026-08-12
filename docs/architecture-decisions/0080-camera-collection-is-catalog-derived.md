# ADR 0080: camera collection is catalog derived

## Status

Accepted for the offline personal Demo.

## Context

The verified media endpoints require a source ID. Hard-coding that ID in a future device page would
create a second inventory and would hide a registered camera whenever its optional media was absent.

## Decision

`GET /api/m8/cameras` derives its inventory from the current source-catalog commit. Safety officers and
operations receive typed camera views; leaders and students receive an empty collection. Each view
binds the exact source and catalog cut, preserves the simulated/non-live/non-life-safety claims, and
publishes authenticated metadata and byte endpoint paths.

If the local binding receipt is absent, the camera remains discoverable with `media_attached=false`
and a null binding. If a receipt exists, the service verifies the current catalog and playback bytes
before returning it as attached. Invalid or drifting authority fails closed rather than silently
downgrading the camera to unattached.

## Consequences

The device page can render current camera inventory without guessing IDs or confusing media absence
with device absence. This read-only collection does not register sources, bind media, transition a
case, dispatch a notification, or expand leader/student access.
