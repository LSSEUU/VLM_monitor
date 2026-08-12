# ADR 0079: recorded media API is verified and role scoped

## Status

Accepted for the offline personal Demo.

## Context

The local binding receipt proves that an exact playback copy exists, but a product interface still
needs bounded browser-compatible reads. A raw static-file mount would bypass persisted actor authority
and could serve bytes after the catalog or local file changed.

## Decision

The loopback API exposes separate metadata and `video/mp4` byte endpoints for the fixed simulated
camera. Both require the existing bearer authenticator and current persisted actor authority. General
camera media is visible only to safety officers and operations; leaders retain global/major-event
scope and students cannot read it.

Each request validates the typed binding receipt and current source-catalog commit. The byte endpoint
opens the playback file once, hashes that handle against the receipt, rewinds the same handle, and then
serves either the full file or one standards-shaped byte range. Invalid ranges return `416` with the
total size. The endpoint performs no decoding, model call, network egress, case transition, identity
inference, face recognition, or cross-camera re-identification.

## Consequences

An authenticated client can fetch metadata and stream the local MP4 with `206 Partial Content` without
turning it into a live-camera or life-safety claim. A future UI may fetch the media as an authenticated
blob; unauthenticated static playback remains intentionally unavailable.
