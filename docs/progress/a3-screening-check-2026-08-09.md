# A3 OpenAI-Compatible Screening Check — 2026-08-09

## Outcome

A3 engineering acceptance is complete for the alpha1 `PPE_GOGGLES_MISSING` path. The final
accepted real-provider smoke used Alibaba Cloud Model Studio
`qwen3-vl-plus-2025-12-19`, reached `READY_FOR_ALERT_POLICY`, passed deterministic procedural
review, and made exactly one provider call. Re-running the same terminal case made no provider
call and did not add a response or completed claim.

This proves the real-pixel A2-to-A3 engineering path and its safety boundaries. It does not prove
model accuracy, deployment readiness, real-site privacy, throughput, or a provider billing total.
The owner-supplied videos visibly identify themselves as AI-generated and are not ground truth.

## Final bound implementation

- Code commit: `803ff1a60f68e01a0263c0f573fafb818b331634`
- Config SHA-256: `e67502ed87615983038e6e70bb1d342d9e2055e2e6c52dd6d38df90c30f972d6`
- Run manifest: `e0ba601f3b083ba6d1f3bf561f8883fa9150cae77f80c91093ea51a73c45f0f3`
- Prompt bundle: `b6a7e737fb9942b41e1b5027a694ec3ee9db55a9a6705b5988d5a806b99291d7`
- Router: `screening-router-v2`
- Provider profile: `pilot-screening`
- Provider: `alibaba-cloud-model-studio`
- Model/revision: `qwen3-vl-plus-2025-12-19 / 2025-12-19`
- Mode: OpenAI-compatible HTTP, verified TLS, one attempt, no transport retry
- Model option: `enable_thinking: false`
- Timeout: 60 seconds for provider and screening coordination
- Pricing authority: CNY ¥1 per million input tokens and CNY ¥10 per million output tokens
- Rule/confirmation: `PPE_GOGGLES_MISSING / STRICT_CAUSAL`
- Secrets: endpoint and API key resolved from User environment variables only; neither value is in
  config serialization, manifests, reports, database output, exceptions, or this document

## Final real-provider receipt

Run `a3-qwen-missing-20260809-v9` processed 241 frames and published one complete,
closure-passing EvidencePack. Exactly three pose-backed temporal eye crops were
`CLOUD_ALLOWED`; the panorama and subject crops remained `LOCAL_ONLY`.

| Field | Receipt |
|---|---|
| Result | `READY_FOR_ALERT_POLICY` |
| Provider calls / repairs / retries | `1 / 0 / 0` |
| Request ID | `19d353e1fc5cb5c75e85e9f8833b66874a6b0053681a48b54b0cd6b99d8637a4` |
| Response ID | `176ece6fb1c9c877a8df7d5216769f6b3e16d374bbf4d4b5694c0c3619bf425a` |
| Input images / pixels | `3 / 75,407` |
| Input / output tokens | `10,971 / 581` |
| Provider latency | `11,097 ms` |
| Persisted estimated cost | `CNY ¥0.016781` |
| Raw response ref | `a3-qwen-missing-20260809-v9/model_responses/176ece6f...425a.json` |
| Raw content SHA-256 | `6572d80fbbcb33201fa8e39fa07caed9c493cb47eb2ebdcd20022f3808cc6c2c` |
| Raw selected content size | `1,604 bytes` |
| Screening result | `818d2b22948f2176424961ef74b4b22b21802dd584b5b71afc1732c42f5ad81e` |
| Verdict | `1a2d6eca5acac4f14dc7979fe9450c893020816a799659898ce953670a8f6a4d` |
| Procedural review | `e9b4658698759a0c68cc6d91b4e54b80e169c87538534656c36a53a50a7d2435` |

The strictly parsed model payload assigned `NOT_WORN` to all three allowlisted crop IDs with
probability `0.92`. It emitted no formal citations and no typed objective claims. LabCourt
deterministically converted only those exact, allowlist-checked observation crop IDs into three
no-coordinate `CROP` citations. It did not infer a citation from prose or let the model decide
evidence existence.

The raw model summaries nevertheless asserted frame-count and dwell conclusions. Under
`screening-router-v2`, those model-authored summaries remain audit-bound in the raw/parsed
screening record but are not copied into the authoritative Verdict. The Verdict instead records a
deterministic narrative that identifies evidence-pack authority, strictly parsed typed fields, and
the versioned policy as its basis. `screening-router-v1` remains unchanged for exact replay of
sealed historical runs.

## Idempotency and cache boundary

Before and after re-running `pilot screen` for the terminal v9 case, SQLite contained exactly one
model response and one completed model-call claim. The second report recorded
`OBSERVED_EXISTING`, `pipeline_invocations: 0`, and no provider call. Unit and integration tests
separately cover the non-terminal cache-hit path; terminal cases short-circuit before that lookup.

## Other sample outcomes and limitations

| Scenario | Run | Outcome | Provider calls |
|---|---|---|---:|
| goggles worn | `a3-qwen-worn-20260809-v2` | `NO_CANDIDATE`; no case | 0 |
| clearly missing, router v1 | `a3-qwen-missing-20260809-v8` | `READY_FOR_ALERT_POLICY` | 1 |
| visually labelled unclear by filename, router v1 | `a3-qwen-unclear-20260809-v2` | `READY_FOR_ALERT_POLICY` | 1 |
| clearly missing, final router v2 | `a3-qwen-missing-20260809-v9` | `READY_FOR_ALERT_POLICY` | 1 |

The `goggles-unclear.mp4` run is not a valid unclear negative control: all three local crops met
the configured observability threshold and Qwen labelled all three `NOT_WORN` at probability
`0.91`. The filename and prior injected labels are not ground truth, so this outcome must not be
reported as either a correct or incorrect prediction. A human-labelled physical-camera set is
required before threshold or accuracy conclusions.

Persisted accepted v8, unclear-v2, and v9 responses have a combined estimated cost of
`CNY ¥0.051515`. A superseded but successfully persisted early response adds `CNY ¥0.016794`.
Several timeout experiments have unknown delivery certainty and might be billable by the
provider. Consequently, these figures are artifact-level estimates, not a claim about the total
provider invoice.

## Failure and replay coverage

- Non-2xx, timeout, network failure, oversized response, malformed envelope, and close failure
  map to typed, redacted provider failures.
- Real timeout experiments entered backlog without an automatic retry. Unknown-delivery claims
  were preserved and were not directly retried.
- Invalid JSON receives at most one structure-repair attempt, then a typed failure.
- External requests are limited to allowlisted `CLOUD_ALLOWED` crops; full-frame, panorama,
  subject, local-only, or mismatched media references are rejected before transport.
- The current lean prompt bundle and the superseded citation-required bundle are both immutable
  and replayable. Historical RunManifests select their exact bundle rather than silently using the
  current prompt.
- Qwen hybrid thinking is disabled for structured JSON mode; parser behavior remains strict and
  contains no permissive free-text recovery.

## Quality evidence

- Final pre-v2 whole-repository split gate: 1,251 contract, 2,183 unit, 1,771 integration, and
  123 E2E tests passed; 7 declared POSIX-only integration tests skipped on Windows.
- Final v2 legacy-replay/domain regression: 222 passed.
- Final v2 A3/pilot/config/HTTP/CLI regression: 204 passed.
- M4 branch coverage: 121 tests, 100%.
- M5 branch coverage: 52 tests, 100%.
- Offline M6 demo: 16 deterministic scenarios passed.
- Ruff formatting/lint, mypy over 510 source files, all 249 generated schemas, and
  `git diff --check` passed for the final code scope.
- A final monolithic `pytest -q` was also attempted after v9, but Windows exceeded the explicit
  60-minute command limit without emitting a countable summary. It is not claimed as a pass and
  does not replace the successful split and directed gates above.

## Preliminary no-network check retained for provenance

The earlier check at commit `50b8bdcf717fddb67f7f2ae5a7911da41e670b58` used an injected
transport and no API key. Worn produced no case; injected `NOT_WORN` labels moved missing to
`READY_FOR_ALERT_POLICY`; injected `UNCLEAR` labels moved unclear to `ESCALATED`. These are typed
engineering fixtures, not model predictions or ground truth. They remain useful evidence that
the fake and real paths share `ScreeningCoordinator`, strict parsing, response persistence/cache,
backlog, routing, and procedural review while differing only at the adapter boundary.
