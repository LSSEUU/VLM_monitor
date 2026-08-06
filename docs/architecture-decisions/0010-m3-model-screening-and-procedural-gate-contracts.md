# ADR 0010: M3 model-call, screening, cache, and procedural-gate contracts

- Status: Accepted
- Date: 2026-07-27

## Context

M3 introduces the first external-model boundary. A provider call can succeed while
its body is empty or structurally invalid, a process can stop between raw-response
publication and parsing, and retries can race with a changed case revision or
evidence pack. Model-authored references and numeric claims are untrusted. The
screening router and procedural gate must therefore be reproducible from explicit
authoritative inputs without treating model prose as structured data.

## Decision

### Prompt and request authority

Every call uses an immutable `PromptManifest` containing the role, prompt ID,
UTF-8 template hash, output-schema hash, renderer/version, and the existing run
prompt-bundle hash. A request binds the run, case, evidence-pack ID and version,
run manifest, model manifest, prompt manifest, rendered prompt, decoding settings,
and the complete call budget. Its evidence whitelist is a stable tuple of typed
`ArtifactRef` values. Media crop references must exactly equal the crop subset of
that whitelist; frame, objective-fact, and tool-result namespaces are also
explicitly authorized.

All persisted M3 identities include `run_id` directly. Computed identities and
computed decisions reject conflicting serialized claims. The M2 schema and run
manifest version remain `2.0.0`; M3 adds contracts without globally changing that
wire version.

### Raw response before parsing

The reliable ordering is:

1. publish the exact provider body at
   `<run_id>/model_responses/<response_id>.json` and verify its bytes;
2. append the immutable `VLMResponse` call receipt in a short transaction;
3. parse the persisted bytes under the request's byte/depth/field/string limits;
4. append `ModelParseReceipt`, including controlled parser defects and hashed
   unknown-reference attempts; and
5. only then create a parsed output and screening result, or enqueue typed retry
   work.

`VLMResponse` is deliberately a pure raw-call receipt. It allows a zero-byte body,
because an HTTP success with an empty body remains auditable malformed output.
Unknown references are not added later by mutating this append-only receipt; they
belong to `ModelParseReceipt`.

The parser accepts one JSON object and validates the exact output contract. The
first structural failure may create exactly one media-free
`StructureRepairRequest`, bound to the original request, response, response hash,
and parser defect codes. An `INVALID_FINAL` receipt is valid only for attempt one.
No permissive free-text recovery is allowed.

### Request-level cache

M3 uses a request-level cache, not a cross-case raw-blob cache. The cache key
includes run, case, evidence-pack ID/version, run manifest, model and prompt
manifests, provider profile and execution location, complete ordered media
identity (crop ID, media hash, privacy transformation and dimensions), all typed
evidence refs, canonical structured text inputs, decoding settings, and all
budgets. SQLite treats `(run_id, cache_key)` as unique and a different response
hash for that key as an integrity failure.

This intentionally guarantees only identical-request retry and process-restart
reuse. If a future milestone needs cross-case semantic reuse, it must split a
scope-free raw-blob cache from run/case/request-scoped response receipts. A
scope-bound `VLMResponse` must never be replayed as another case's receipt.

### Deterministic screening

The provider JSON is parsed first as `ScreeningModelPayload`, which contains only
strict typed labels, citations, summaries, and objective claims. It has no run,
case, request, response, manifest, model-authoritative visibility, or evidence-
existence field. Only after that strict parse and unknown-reference pre-scan does
the system wrap the payload in a scoped `ParsedScreeningOutput`. Objective counts
and durations remain typed claims tied to `OBJECTIVE_FACT` references and are
checked later against authoritative facts; numbers are never extracted from
summaries.

Every citation bounding box uses the single explicit
`CITED_ARTIFACT_PIXELS` coordinate space: coordinates are local pixels of the
cited crop or frame, never implicit original-frame coordinates. The contract
checks structural geometry and the later gate checks the box against the cited
artifact's authoritative width and height.

Presence routing uses versioned low/high thresholds. A versioned strong-signal
policy computes, rather than accepts, `STRONG_SIGNAL_CONFLICT` when the pack's L1
score is strong and the presence model route would be `NOT_ESTABLISHED`.

Absence routing uses only pack-authoritative temporal crop IDs, clear crop IDs,
and required clear count. Every authoritative clear crop must have exactly one
label before `ESTABLISHED`; all those labels must be `NOT_WORN`, and the count must
meet the rule. A clear `WORN` label yields `NOT_ESTABLISHED`; missing, unclear, or
insufficient clear labels yield `ESCALATE`. Labels for non-clear crops do not
vote. Post-threshold correction context is a typed `FrameId`, never an invented
crop, and `Case` rechecks it against the pack confirmation record. `Case` also
rechecks the complete absence authority tuple and the L1 score against the exact
referenced pack.

### Verdict and procedural review

`Verdict` and `ProceduralReview` are separate append-only roots. A verdict retains
even semantically invalid proposals so the gate can record why they were rejected;
`Case` therefore checks scope and identity but does not erase a violation-type
mismatch before L5 can report it. `ProceduralReview.passed` is computed solely from
its stable defect tuple.

The fourteen defect codes have an explicit non-alphabetic taxonomy order. The
first three are parser-origin defects targeting a model response. The remaining
eleven are deterministic-gate defects targeting a verdict. Each code has a fixed
origin, reason-code set, field, typed-reference context, and optional value-hash
rule. Provider exceptions, raw values, host paths, and open detail strings are not
part of public defects. Precedent checks use a narrow, case-scoped lookup receipt
that distinguishes `FOUND`, `NOT_FOUND`, and `NOT_VISIBLE`, carries an active
snapshot only when found, and records the authoritative similarity.

Case state is evidence-bearing: `SCREENED` has a screening result, `ESCALATED`
has a latest `ESCALATE` result, `REWORK_REQUIRED` has a latest failed review,
`READY_FOR_ALERT_POLICY` has a latest passed review for the latest verdict, and
`BACKLOGGED` binds a content-addressed current backlog item. Passing review only
makes a case eligible for a later alert-policy milestone; M3 sends no alert.

### Durable backlog

A backlog item has a run/case/stage/role/reason and immutable stage-input binding.
Leasing increments the bounded attempt count and requires a lease ID, hashed owner,
and UTC expiry. Completion and release use the expected lease ID as their CAS
token. Expired leases are reclaimed with a caller-supplied cutoff and limit; wall
clock time is never read as adjudication evidence. Exhausting the retry budget
transitions to explicit `EXHAUSTED` state for the human path instead of leaving
work permanently pending or leased.

## Consequences

- Raw provider output is recoverable and auditable even if parsing crashes.
- One malformed response can cause at most one structural repair call and never
  causes an additional media disclosure.
- Cache hits cannot silently cross run, case, pack, privacy, model, prompt, or
  budget scope.
- Model prose, visibility guesses, and fabricated references cannot become
  objective authority.
- Failed verdicts and their deterministic defects remain immutable history.
- Backlog workers can recover from crashes without an old lease completing newer
  work.
- Exact golden identity vectors, JSON Schema snapshots, and Python contract tests
  are release gates for future changes to these semantics.
