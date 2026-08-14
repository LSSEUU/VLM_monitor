# ADR 0095: M8 separates evidence quality, calibrated risk, and semantic hearing

## Status

Accepted.

## Context

The frozen M3 contract retains a provider-authored `violation_probability`, while absence
routing is controlled by typed clear-crop observations. Treating both as one confidence
authority conflates whether pixels are usable, how likely a violation is under a labelled
local population, and how a semantic reviewer explains the evidence. Objective insufficiency
also caused three hearing roles to receive the same missing information before any acquisition
capability was checked.

M4 v1 requires at least one `Detection` for high-resolution redetection and has no typed
per-frame series. Real tools may legitimately return no detections or a complete confidence
curve, so forcing those outputs into v1 would require fabricated objects or untyped encoding.

## Decision

M8 adds three adjacent, content-bound authorities without changing frozen M0-M6 wire
contracts:

1. Evidence quality derives only from objective observability inputs and decides whether an
   established semantic claim is procedurally supportable. It never suppresses an L1
   candidate.
2. Event risk is an offline, human-labelled, detector-feature calibration artifact. It starts
   in shadow mode and never falls back to provider-authored probability.
3. Semantic hearing is entered only after the evidence is objectively sufficient and the
   typed M3 result still conflicts or escalates.

For an absence case with fewer than the required clear crops, M8 creates a persisted
pre-hearing preparation before any Prosecutor, Defender, or Judge call. It may publish at
most one ordinary M2 successor and rerun L3 once. If the immutable source cannot provide new
clear evidence, the case enters typed human review without a hearing session.

M8 acquisition v2 records legitimate empty redetection and typed confidence series. Results
representable by M4 v1 may be bridged to its existing successor machinery. Empty detection or
other unrepresentable results remain adjacent audit authority and cause explicit human review;
no sentinel detection or free-text series is permitted.

## Consequences

- Historical Cases, EvidencePacks, hearings, Verdicts, and receipts are not rewritten.
- A model's self-reported score remains auditable but is not presented as calibrated
  probability.
- Single-camera runs advertise `OTHER_CAMERA_SAME_TIME` as unavailable.
- An active calibrated router requires a future versioned screening authority; shadow
  calibration in M8 cannot silently mutate frozen M3 semantics.
