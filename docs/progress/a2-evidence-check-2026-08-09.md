# A2 Real Candidate and Evidence Check — 2026-08-09

This is a sample-backed engineering check, not a labeled evaluation, accuracy claim, or real-site
acceptance. All three inputs visibly identify themselves as AI-generated. Source video, SQLite,
raw responses, and generated images remain under the Git-ignored local `inputs/` and `runs/`
boundaries.

## Bound implementation

- Code commit: `5d9eb02ede493c2862a0b1749c4e7180b1e4465c`
- Config SHA-256: `0a537f3521e1c8dd824a5a1a560611be166fee73aa70a2b7000ec162afffabe7`
- Perception manifest: `94aeb1b6847c0b387a385d2e5b47943e8ed2e2cb0dc2000200bc5c964111853c`
- Rule: `PPE_GOGGLES_MISSING`
- Confirmation: `STRICT_CAUSAL`
- L0 persistence: aggregate count only, with no reminder body, subject ID, or track history
- External media: panorama is forbidden and every body-fallback crop is `LOCAL_ONLY`

## Content-derived results

| Scenario | Final run | Associations | L0 reminders | Candidate events | Evidence packs | State |
|---|---|---:|---:|---:|---:|---|
| goggles worn | `a2-field-worn-20260809-v1` | 241 | 0 | 0 | 0 | `NO_CANDIDATE` |
| goggles clearly missing | `a2-field-missing-20260809-v2` | 241 | 1 | 1 | 1 | `EVIDENCE_READY` |
| occluded/unclear | `a2-field-unclear-20260809-v1` | 149 | 1 | 1 | 1 | `EVIDENCE_READY` |

The missing and unclear packs each contain one fully redacted panorama, one fully redacted subject
crop, and three local-only temporal head anchors. Both packs are complete and pass the existing
repository closure verification. No VLM was called.

The missing case is `2ee434cc-3f72-58a4-8992-19b39a20788d`; its pack is
`5b95807e9245c40c5d455af3f5aa18254de32d7a737397cf10dba829fc19ee9b`. A real resume returned the
same report and left the A1 completion seal timestamp unchanged.

The unclear case is `7b716fff-fdaa-56b9-9ca4-171089528df5`; its pack is
`66d68b50bc6ca331ad3c4a77dadf4357d3167c19916cb8aaf36f1dbfb7931780`.

## Crop inspection

- Clearly missing: all three temporal crops select the intended person and contain the face/eye
  area needed to see that goggles are absent. Because the geometry comes from the person-box head
  fallback rather than verified eye keypoints, the face remains visible and the receipt is
  `BODY_FALLBACK_REGION_LOCAL_ONLY`. These pixels cannot enter an external VLM request.
- Occluded/unclear: the selected crops show the back of the lowered head and upper lab coat, not a
  usable eye region. Their computed observability totals are approximately `0.373`, below the
  configured clear threshold `0.65`. The pack therefore preserves the ambiguous causal event but
  does not supply enough clear evidence to establish the allegation.
- The unclear sample proves that the allowed first-pass upper-person-box fallback is not robust to
  a lowered posture. Before external A3 screening can receive useful privacy-bounded pixels, add a
  pinned local pose/eye localization component with offline weights, raw result receipts, timeout,
  cache, manifest, and failure states. Do not synthesize or guess keypoints.

## Quality gates

- Ruff format: 927 files checked.
- Ruff lint and mypy: 511 source files checked.
- Schemas: 248 exported schemas verified without drift.
- Unit: 2,159 passed.
- Contract: 1,242 passed after adding the two A2 schemas to the explicit public registry.
- Integration: 1,764 passed; 7 POSIX-only cases skipped on Windows.
- E2E: 123 passed.
- M4 and M5 branch coverage gates: 100%.

These counts describe executed checks only. They are not product accuracy, throughput, latency, or
cost measurements.
