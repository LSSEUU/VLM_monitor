# UI-MVP Check — 2026-08-10

## Outcome

The existing A0–A5 pilot can now be demonstrated through a local Chinese browser interface. The
page exposes video selection, five-stage progress, video preview, evidence timeline, case detail,
and the local alert center without changing the existing authority model.

## Contract

- `PilotUiDashboard` is a strict, versioned projection with fixed stage order and local-only media
  URLs.
- `PilotUiJobStartRequest` accepts an opaque video handle and a bounded portable run ID; it never
  accepts an arbitrary filesystem path or API credential.
- `PilotUiJobStatus` permits one explicit state transition chain:
  `IDLE -> RUNNING -> COMPLETE | ATTENTION_REQUIRED | FAILED`.
- `PilotUiErrorResponse` exposes stable reason codes instead of exception text.
- Four JSON Schemas are registered and checked into `schemas/`.

## State and authority

The UI starts new work only through the existing `build_pilot_run_request` and `run_pilot_a5`
boundaries. Displayed objective counts, timing, coordinates, evidence existence, case state, appeal
state, and alert state are read from existing typed artifacts. Model prose does not create UI facts.
Production delivery remains exactly zero.

Only complete metrics-backed runs are offered as existing results. Evidence is reopened through the
secure workspace boundary and hashed before every response; missing or changed bytes fail closed.
The browser receives neither the model endpoint nor the API key.

## Scenario coverage

- Empty selector and preview-only state.
- Complete A5 run with one case, five evidence images, timeline, upheld appeal, and active local alert.
- Evidence tamper and unverified-media refusal.
- Partial internal-run hiding.
- Single-job concurrency and sanitized background failure.
- HTTP Host/origin boundary, CSP/security headers, byte-range video, evidence endpoint, and job API.
- Offline asset policy, keyboard focus, minimum 44-pixel controls, responsive layout, and reduced
  motion.

## Verification artifact

- 42 directed automated checks passed.
- The full split regression passed 1,262 contract, 2,187 unit, 1,786 integration, and 124 E2E
  checks; 7 declared POSIX-only integration checks were skipped on Windows.
- Ruff verified all 949 formatted files and full-repository lint passed.
- Mypy passed all 522 source files.
- 262 generated schemas matched the checked-in snapshots.
- Real-browser QA passed at 1440×1000 and 375×812 with no horizontal overflow or browser logs.
- The existing `goggles-missing.mp4` H.264 source was playable and reached ready state 4.

These checks establish UI workflow integrity, not detector/VLM accuracy, real-site latency,
throughput, provider cost, or safety performance.

## Manifest impact

None. The UI does not mutate historical RunManifest identity or add a second authority. A new job
creates the normal A5 artifacts and manifests through the existing orchestrator; viewing an existing
run is read-only apart from standard HTTP access logs, which contain no API key or model response.
