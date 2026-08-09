# A1 Sample Video Check — 2026-08-08

## Scope and authority

This record documents a provisional engineering check of the three short MP4 files supplied by
the project owner. It is not a labeled evaluation set, ground truth, an accuracy benchmark, or a
real-site acceptance. The source frames and generated previews remain under the Git-ignored
`inputs/` and `runs/` boundaries; no image is committed.

All three source videos visibly contain a `豆包AI生成` watermark. They are useful for verifying
the real detector/tracker pipeline and for provisional threshold calibration, but they cannot
validate a physical camera, a real laboratory population, or the `hood-01` risk polygon.

## Reproducible inputs and execution

All inputs are 1280×720, caller-attested constant-frame-rate streams at 24 fps with 241 decoded
frames. The final runs use the same execution manifest:

```text
manifest_id = 94aeb1b6847c0b387a385d2e5b47943e8ed2e2cb0dc2000200bc5c964111853c
score_threshold = 0.50
goggles_nms_iou_threshold = 0.95
empty_detection_policy = TRANSFORMERS_EMPTY_TEXT_LABEL_SENTINEL_V1
```

| Scenario | Input SHA-256 | Final run | Completion ID |
|---|---|---|---|
| goggles worn | `a3dae5a59000d12fdcadf068af2b4cb2cf6bdcae755f240bfdc6ce95ba47707d` | `a1-field-worn-20260808-v3` | `919ebff42c9f46a8bf083752e3094342d47ecfc2b9f6be47929ef2420c6deace` |
| goggles clearly missing | `774e04b2a9f03135eecc5983454b8f006b891d829d29f0a7c1fef7bcf2d69726` | `a1-field-missing-20260808-v4` | `2cd57477e68d4710e9ab253471522ded43884535708e608d559df67d3652a0ad` |
| occluded/unclear | `4bd6c5939c4cbb9e48b1856582ad754c4b42107a2078bccd324536b546632fef` | `a1-field-unclear-20260808-v2` | `dacad3e910ad50e81911456a0342225f9af73c7267166f82c8cf17580c9a4ddf` |

Each completion ID seals the ordered artifact inventory, sizes, hashes, frame identities,
receipts, raw responses, derived detections, aggregate counts, and preview. A second invocation of
each final run accepted the completion seal and returned the same report without another detector
call.

## Descriptive results

These are artifact counts, not detector-quality metrics.

| Scenario | Frames | Person detections | Goggles detections | Anonymous tracks | Provider failures |
|---|---:|---:|---:|---:|---:|
| goggles worn | 241 | 241 | 241 | 1 | 0 |
| goggles clearly missing | 241 | 241 | 0 | 1 | 0 |
| occluded/unclear | 241 | 235 | 115 | 1 | 0 |

Provisional engineering visual review of five evenly sampled preview frames per video found:

- Worn: person boxes and the anonymous track are continuous in the samples; goggles boxes are
  consistently located over the transparent eyewear.
- Clearly missing: person boxes and the anonymous track are continuous in the samples; no
  above-threshold goggles box is rendered.
- Occluded/unclear: person boxes are mostly continuous; goggles candidates are intermittent and
  several sampled boxes fall around the back or side of the head. This output must remain
  ambiguous downstream and must not be interpreted as proof of either worn or missing PPE.

Before class-wise NMS, the worn video produced nearly coincident `protective eyewear` and
`safety goggles` prompt matches in every frame. An IoU threshold of 0.95 now removes only these
near-duplicate goggles boxes. The exact empty postprocessor sentinel emitted on the missing video
is normalized to a successful empty detection; any other box/score/label length mismatch remains
a typed frame failure.

The provisional score threshold changed from 0.35 to 0.50 because the highest per-frame goggles
candidate in the clearly-missing sample remained below 0.44, while the highest candidate in every
worn frame remained above 0.55. The unclear sample intentionally remains mixed at this boundary.
This three-video separation is configuration evidence only and makes no generalization claim.

## Remaining A1 owner decisions

1. Completed 2026-08-09: the project owner approved all three local previews for the A2 sample.
2. Completed 2026-08-09: the project owner approved the displayed sample polygon. A deterministic
   footpoint check then showed that its `y=700` lower edge excluded every person frame in the worn
   and missing samples because the tracked boxes end at `y=720`. The implementation preserves the
   approved left, top, and right edges and extends only the lower edge to the 720-pixel frame
   boundary: `[(120,90), (980,90), (980,720), (120,720)]`. This yields 241 contiguous in-zone
   frames for worn, 241 for missing, and 149 for unclear. The alpha1 zone is also narrowed to its
   sole selected rule, `GOGGLES`; it no longer declares unsupported `LAB_COAT` detection authority.
3. Still required before deployment: supply a short authorized capture from the intended physical
   camera before making a real-site
   or deployment-readiness claim. The three AI-generated samples do not establish that claim.

A2 engineering work is now authorized. Decision 3 is a later real-site and release gate, not a
reason to block the sample-backed implementation.
