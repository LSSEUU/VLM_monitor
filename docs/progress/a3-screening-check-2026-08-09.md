# A3 OpenAI-Compatible Screening Check — 2026-08-09

This is a no-network engineering check over the three owner-approved sample videos. It proves the
real-pixel A2-to-A3 control flow, not VLM quality. Per-frame labels in this check were deliberately
injected as typed test data; they are not model predictions or ground truth. The visibly
AI-generated sample videos also remain unsuitable for real-site acceptance.

## Bound implementation

- Code commit: `50b8bdcf717fddb67f7f2ae5a7911da41e670b58`
- External-validation config SHA-256: `709193f60455caa45117a52efaa18726d9141f1da89f1983b171711fb48c5374`
- Adapter identity: `openai-compatible / injected-validation-vlm / 2026-08-09`
- Transport: injected, no network and no API key
- Rule: `PPE_GOGGLES_MISSING`
- Confirmation: `STRICT_CAUSAL`
- Privacy: only the three pose-backed temporal eye crops are `CLOUD_ALLOWED`; panorama and subject
  crops remain `LOCAL_ONLY`

## Content-derived pipeline results

| Scenario | Run | A2 | A3 case state | Model responses |
|---|---|---|---|---:|
| goggles worn | `a3-injected-worn-20260809-v1` | `NO_CANDIDATE` | no case | 0 |
| goggles clearly missing | `a3-injected-missing-20260809-v1` | `EVIDENCE_READY` | `READY_FOR_ALERT_POLICY` | 1 |
| occluded/unclear | `a3-injected-unclear-20260809-v1` | `EVIDENCE_READY` | `ESCALATED` | 1 |

The missing and unclear EvidencePacks each exposed exactly three cloud-allowed temporal crops to
the request builder. The injected transport was called once for each case. The stored selected raw
content was reopened from its content-addressed path and matched the database SHA-256 and byte
count. Missing used only `NOT_WORN` observations; unclear used only `UNCLEAR` observations. The
deterministic router therefore established the first and escalated the second without using VLM
text for objective counts, duration, coordinates, or evidence existence.

## Implemented A3 boundaries

- `StdlibOpenAICompatibleTransport` performs one verified-TLS POST and no retry.
- Connect and read use the request timeout; responses are read at most
  `max_response_bytes + 1` bytes.
- Non-2xx, timeout, network, oversized-response, malformed-envelope, and close failures become
  typed, redacted provider failures.
- Endpoint and API key are resolved only inside the adapter from named environment variables.
  They do not enter config serialization, manifests, reports, database rows, or exceptions.
- The real provider path reuses `ScreeningCoordinator`, prompt catalog and registry, response
  store/cache, strict parser, one structure-repair attempt, backlog, and procedural verifier.
- `labcourt pilot screen` exposes bounded A3 processing without changing the offline A1/A2
  default.

## Directed quality gates

- 157 A3-related unit, contract, integration, CLI, schema, and legacy M3 regression tests passed.
- All 249 generated schemas verified without drift.
- Ruff, mypy, and `git diff --check` passed for the changed scope.
- The prior exhaustive A2 gate remains the latest whole-repository gate; a new exhaustive gate is
  required after the first real-provider smoke and before A3 is declared complete.

These results make no accuracy, latency, throughput, or cost claim. A real-provider smoke remains
pending the operator-supplied endpoint, model identity, explicit token pricing, and API key through
the environment only.
