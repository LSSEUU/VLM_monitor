# ADR 0078: recorded media binding is an exact local copy

## Status

Accepted for the offline personal Demo.

## Context

The revision-2 camera catalog intentionally registered a simulated recorded-video source without
claiming that media existed. An authorized MP4 is now available locally, but changing the existing
camera registration receipt would break its replay identity. Requiring OpenCV or ffprobe at runtime
would also expand the default dependency boundary for a task that only needs browser playback.

## Decision

Media binding is a separate content-addressed receipt anchored to the current camera catalog cut.
The binder opens the input once, checks its ISO-BMFF `ftyp` signature, hashes and copies the exact
bytes into the ignored local Demo directory, and proves that the input and playback hashes and sizes
match. It does not transcode, modify the original, decode frames, use a network or GPU, or perform
face recognition or cross-camera re-identification. Existing conflicting playback bytes fail closed.

The Windows camera and start entries choose `inputs/goggles-missing.mp4` when present and otherwise
choose the first MP4 by stable filename order. The output always retains the
`SIMULATED · RECORDED VIDEO` badge and is not eligible as a live or life-safety source.

## Consequences

The original camera registration remains replayable with `media_attached=false`, while the additive
binding receipt proves that playback media is attached. Browser/API playback is a subsequent slice;
decoder metadata and frame-level evidence are not inferred by this binding receipt.
