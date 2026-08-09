# A5 Replay and Recovery Check — 2026-08-10

## Scope

- Final real source run: `a3-qwen-missing-20260809-v9`
- Source RunManifest code commit: `803ff1a`
- Run manifest: `e0ba601f3b083ba6d1f3bf561f8883fa9150cae77f80c91093ea51a73c45f0f3`
- Config SHA-256: `e67502ed87615983038e6e70bb1d342d9e2055e2e6c52dd6d38df90c30f972d6`
- Reproducibility mode: `REPLAY_LOCKED`
- Delivery boundary: local JSON only; production delivery count `0`

This check establishes restart, provider-trap, idempotency, and artifact-integrity behavior. It does
not establish detector/VLM accuracy, real-site readiness, or punishment-grade evidence.

## Complete Pilot Command

`labcourt pilot run` now performs one bounded, restart-safe orchestration:

1. execute or validate and resume sealed A1/A2 artifacts;
2. retry at most one pre-existing screening backlog item;
3. process bounded newly ready screening work;
4. close eligible cases, dispatch only to the local JSON channel, and republish the operator report.

The command returns the content-bound `pilot-a5-run-report-v1` contract. An unresolved backlog,
escalation, human-review requirement, or alert-delivery problem produces `ATTENTION_REQUIRED` and
exit code `1`; malformed or failed stage boundaries return a sanitized typed failure and exit code
`2`.

For historical `REPLAY_LOCKED` runs, A5 reads the original `code_commit` only from the verified,
run-scoped persisted RunManifest. A2 then performs its existing exact whole-manifest comparison.
This permits a newer CLI to resume a valid historical run without allowing config, model, prompt,
rule, perception, or artifact identity drift.

## Real Run Replay

The complete command was executed twice against the final real-provider run and the owner-approved
source video. Both invocations returned byte-identical canonical JSON:

- A5 report ID: `2ce0a42ef940832b819980d810b44243e24e9789a986ca4940adb152338610dc`
- State: `COMPLETE`
- A2 report ID: `da01f572e1faabd6209f2b1decf13236986e3282b38160c670a9cf6f8f8917d4`
- Backlog result: `NO_WORK`
- A3 selected cases: `1`; pipeline invocations: `0`; cache hits: `0`
- A4 closure selected: `0`; dispatch selected: `0`
- Publication ID: `424e03267bc794fc2a0224743209b7d20d1e9e7572d9c386f958d1fad3b548db`
- Metrics ID: `cf5092075259fd3361a166895a390363fad69b6a0897dbfb314c6fe7c26bc399`
- Case state: `APPEAL_RESOLVED`, revision `8`, appeal `UPHELD`
- Final decision: `ESTABLISHED`; local alert remains active
- Production delivery count: `0`

The one selected A3 case was observed in its existing terminal state. No screening pipeline or
provider path was invoked. SQLite retained exactly one Case, one EvidencePack, one model-call
claim, one model response, one usage record, one Alert, one outbox item, one dispatch attempt, and
one dispatch receipt. It retained three append-only appeal versions and eight Case versions. There
were no backlog items, alert rescissions, or training labels.

Stable replay artifacts included:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `perception/completion-manifest.json` | 2,211 | `109a59665e7b4e38ce670f27cc0e87243f711329540fde9fff10d4d7fa82844a` |
| `pilot/a2-report.json` | 1,366 | `be12af1afcf0e391e94790f46670608c8ed1b19e9a543661372d74aed8f472aa` |
| `metrics.json` | 3,999 | `4ec8cab5e1eedd37c293181a50887118be89451b489d2b1247611c4c02b539da` |
| `report/index.html` | 10,544 | `0f7ab73aed0384a94f95b044ad210ee40bd5e8829b222dddc8bef8bf212fb35e` |
| `alerts/c492c8e7c5af2310087f37cbc9f392723aa3c77951565df998fa4b46f03f0314.json` | 1,065 | `560b190378b9bd035ddc94eed90139542cd35cedbf898f30ebdb83f5f6754f34` |

Two final read-only artifact validations returned byte-identical JSON, report ID
`6b350c3d302e9c33e84e87a507ad3e8c097603b3ac53144d95922a0d5af11453`, and zero
issues. M2 validated one Case and five media files; M3 validated nine documents and one physical
raw response; M5 validated fifteen authority rows and six projection files.

## Restart and Provider-Trap E2E

The offline A5 E2E used deterministic real-pixel test frames and strict injected transports:

1. A definitely-not-sent provider timeout created one `BACKLOGGED` Case and no Alert.
2. The next full run reused the sealed A1/A2 artifacts, retried the original backlog item, reused
   the original Case, completed screening, and emitted exactly one local Alert.
3. Two terminal replays used detector and VLM transports that raise immediately if called. Neither
   trap was reached; both reports were identical.
4. Case, backlog, Alert, outbox, attempt, and receipt row counts remained stable across the terminal
   replays.

An unknown-delivery timeout intentionally does not auto-resend. It remains subject to the existing
provider-free model-response recovery and human-attention boundary so the system cannot silently
duplicate a potentially delivered and billable request.

## Quality Gates

- A5 directed contract/CLI/restart gate: `18 passed`; after the final CLI attention assertion, its
  focused node also passed.
- Expanded pilot, artifact, and appeal regression gate: `296 passed`.
- Full split test gate: `1,258 contract`, `2,186 unit`, `1,778 integration`, and `124 E2E` passed;
  seven declared POSIX-only integration cases skipped on Windows.
- Ruff: all `941` files formatted; full lint passed.
- Mypy: all `518` source files passed.
- JSON Schema: all `258` checked-in schemas verified without drift.
- M4 branch gate: `121 passed`, `100.00%`.
- M5 branch gate: `52 passed`, `100.00%`.
- Offline M6 demo: all `16` scenarios passed.

This completes A5 engineering acceptance and the A0–A5 `v0.2.0-alpha1` engineering scope.
