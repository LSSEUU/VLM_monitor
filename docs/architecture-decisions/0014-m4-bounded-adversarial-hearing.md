# ADR 0014: M4 bounded adversarial hearing and acquisition authority

- Status: Accepted
- Date: 2026-07-28

## Context

M4 advances an escalated case through independently configured prosecutor,
defender, and judge roles. The judge may either propose a verdict or request one
of five deterministic acquisition tools. A proposed verdict can fail the M3
procedural gate and be reworked. Provider interruption, malformed role output,
tool failure, process interruption, and concurrent case changes must not create
an unaudited partial hearing, reset a budget, repeat a side effect, or turn model
text into objective authority.

The frozen M3 model-call contracts are screening-specific: their purpose,
attempt, parser, and repair semantics cannot represent a hearing role. The M2
pack publication transaction also moves a case to `EVIDENCE_READY`, which is not
a valid acquisition transition inside a hearing. Extending either frozen
interface would make an earlier milestone silently acquire new semantics.

## Decision

### Independent M4 roots

M4 adds independent, content-addressed roots for:

- one immutable hearing session authority and append-only phase checkpoints;
- hearing model requests, responses, cache entries, and strict parse receipts;
- exactly-once provider-usage receipts and one auditable precedent-retrieval
  receipt per logical cycle;
- prosecutor, defender, and judge role outputs;
- acquisition requests, execution manifests, results, and receipts;
- hearing rounds and the complete hearing record;
- a `HearingVerdictBinding` that binds every persisted terminal judge proposal
  and hearing record to the existing frozen `Verdict`; and
- a `HearingHumanReviewReceipt` for every direct M4 human transition.

The serialized field shape, generated schema, and computed identity rules of
`Case`, `EvidencePack`, `Verdict`, and the M3 model-call contracts remain
unchanged. M4 extends only the `Case` aggregate validator, SQLite transition
verifier, and read-only reconstruction rules so that the unchanged
`TimelineEntry` shape can carry a typed M4 human-review receipt. `EvidencePack`
and `Verdict` semantic validators remain unchanged. SQLite remains the
authority; JSON is a rebuildable projection.

Every role request binds the run, case, exact pack ID/version, hearing and round
identity, acquisition and rework counters, role/profile/model/prompt manifests,
ordered media and evidence whitelist, canonical structured inputs, decoding
settings, complete call budget, and run manifest. Provider-authored JSON contains
no system identity. The system adds scope only after a strict, bounded parse.
Unknown references remain explicit diagnostics and are never corrected to a
nearby ID.

`RunManifest.prompt_bundle_sha256` is already frozen as the M3 screening bundle.
M4 therefore does not reinterpret that field or weaken the M3 equality check.
The immutable hearing session adds an M4-only
`hearing_prompt_bundle_sha256`, binds it to the three role prompt manifests and
the existing run manifest, and the application checks it against a separately
frozen M4 bundle constant. This additive execution authority makes both bundles
auditable without changing the identity of an existing run or any frozen M3
request.

Raw response bytes are published before parsing under the existing private
`<run_id>/model_responses/` boundary. M4 receipts use their own request and role
semantics while retaining the same content-addressed, owner-only, journaled
publication guarantees. A valid cache hit is fully reverified before reuse.

### Hearing state machine and global budgets

A hearing may start from `ESCALATED` or `REWORK_REQUIRED`. For an initial
`REWORK_REQUIRED` entry with no active hearing, the latest Verdict and latest
failed ProceduralReview must be exactly bound to the current pack; their typed
defects become the initial hearing context. This creates cycle 1 with
`rework_rounds_started=0`: the earlier M3 failure does not consume an M4 rework
round. For an already active hearing, `REWORK_REQUIRED` may resume only an exact
`REWORK_READY` checkpoint produced by the latest hearing-bound failed review.
Starting or resuming atomically moves the case to `DELIBERATING` before external
calls.

One hearing cycle is ordered:

1. retrieve a bounded, controlled precedent context;
2. call the prosecutor;
3. call the defender with the prosecutor output;
4. call the judge with both argument sets and the precedent context; and
5. either execute exactly one acquisition request or build one proposed verdict.

After acquisition, all three roles run again against the new pack version. After
a failed procedural review, all three roles run again as one rework cycle. The
acquisition budget is global for the hearing and never resets during rework.
The maximum number of logical Judge decision cycles is derived, not
independently configurable:

```text
1 initial + max_acquisition_rounds (2) + max_rework_rounds (2) = 5
```

These dimensions are additive, never multiplicative. Acquisition ordinals and
rework ordinals are contiguous. The judge cannot request two tools in one round,
and a round cannot contain both a final proposal and an acquisition execution.

`rework_rounds_started` counts additional hearing cycles actually opened after
a failed hearing Verdict; it does not count failed proposals. On a failed
review, if this count is below the configured maximum, it is incremented and
authorizes exactly one next cycle. If it already equals the maximum, no new
cycle is created and the Case moves to human review. With a maximum of two, the
first and second failed proposals open rework cycles 1 and 2; the third failed
proposal moves to human review.

A failed review first commits Verdict, HearingVerdictBinding,
ProceduralReview, Case=`REWORK_REQUIRED`, and hearing
phase=`REWORK_READY` atomically. A separate adjacent transition starts the next
cycle and changes the Case to `DELIBERATING`. The bounded driver may execute
both transitions in one invocation, but they remain two persisted revisions.

`max_judge_cycles` bounds logical `JudgeDecisionRequest` cycles, not every
provider invocation. Each primary role request may authorize at most one
media-free `HearingStructureRepairRequest`, bound to the exact original
request, response hash, original role, cycle, output schema, and parser defects.
The repair response may contain only the same role's typed payload; even a
Judge `FINAL` or `ACQUISITION` payload remains inert until strict parsing and
system scoping produce the authoritative role output. Repair never creates a
Verdict or executable acquisition request by itself and does not create a new
hearing cycle. It does count toward cumulative tokens, cost, usage, and provider
requests.

`max_total_images` counts every media item in every primary role request,
including redisclosure of the same crop to another role or cycle. Structure
repair is media-free. `max_total_output_tokens` counts every newly persisted
primary or repair response across the hearing and backlog generations. Recovery
or cache reuse of the same exact response is accounted exactly once and never
resets either budget.

Image disclosure is reserved atomically when the request-level call claim is
created, before entering the provider boundary. Lease takeover of the same
request does not reserve it again; a new proven parse-failure generation does.
This deliberately counts a request whose transport later proves it was not sent
as a conservative reservation, so provider outages cannot be used to bypass
the session limit. Output tokens are atomically accounted with the exact
persisted response and its usage receipt.

Budget exhaustion never permits the system to rewrite a Judge decision. If an
already parsed terminal Judge payload explicitly has
`decision=INSUFFICIENT_EVIDENCE`, the builder and L5 may finish it without
another model call. If the only Judge output is an acquisition request after
the acquisition budget is exhausted, or if rework is exhausted after an
invalid proposal, the Case moves to typed human review.

### Role and failure isolation

Prosecutor, defender, and judge profiles are resolved independently. Tests drive
each role from independent fake fixtures. There is no silent role substitution
and no fallback to another model. A provider failure, or a strict-output failure
remaining after the sole authorized structural repair, creates a `HEARING`
backlog item for the exact original role and exact primary-or-repair
request/checkpoint, and moves the case to `BACKLOGGED` atomically. A provider
interruption or crash resumes the exact unfinished call. Two persisted strict
parse failures authorize one new retry generation, which restarts only that
role's primary call and grants only that generation's single repair allowance;
it never repeats earlier completed roles or restarts the case. No path resets
session budgets.

An embedding or precedent-context degradation is not a model-role substitution.
The hearing may proceed with an explicit degraded-retrieval receipt and an empty
or partially available controlled context. The final record preserves the
degraded flag. M5 replaces the deterministic fake retrieval implementation with
the production precedent store.

M4 reuses the shared immutable `BacklogItem` lease history, whose existing
`HEARING` roles and `MODEL_REQUEST` artifact kind need no new serialized field or
enum. Its validator matrix is extended to allow that exact request reference.
The stage input hash binds the request document, which in turn binds the hearing,
cycle, phase, pack, original role, and primary-or-repair checkpoint. M4 uses a
stage-specific retry context and completion receipt. The M3 screening worker
remains unable to lease or reclaim `HEARING` items. Every historical exit from a
hearing lease has exactly one M4 completion authority, and stale lease or case
revision cannot commit.

Three failure closures remain intentionally distinct. A provider retry failure
that is proven `DEFINITELY_NOT_SENT` closes its exact lease-generation call with
a `RETRY_FAILURE` model-call authority; its claim owner is persisted only as a
digest, and the closure binds the claim takeover count and completion receipt.
A strict parse failure instead preserves the returned responses, strict proof,
typed retry outcome, and completion receipt; it is not mislabeled as a provider
failure. Reclaiming an expired worker lease produces `WORKER_LEASE_EXPIRED`,
bound to the immutable backlog stage input and optional exact resume-request
reference. Lease expiry carries no response references, strict parse proof, or
model-call failure authority, because expiry is not evidence that a provider
failed. All three histories are reloadable and contiguous, but only proven
strict parse failure advances the retry generation.

### Acquisition is deterministic authority

The only actions are:

- `REQUEST_MORE_FRAMES`;
- `RECROP`;
- `OTHER_CAMERA_SAME_TIME`;
- `TRACK_CONFIDENCE_CURVE`; and
- `REDETECT_HIGH_RES`.

Their discriminated parameter models contain no arbitrary host path, SQL, shell,
URI, or free-form executable field. The executor validates that every input
belongs to the current pack or an explicitly authorized camera/time scope. It
records the exact request, validated parameters, input and output refs, tool
implementation/model manifest, and execution receipt before publishing a new
pack version.

Tool execution has a durable, typed fence separate from pack publication. The
claim uses the acquisition request ID as its idempotency key and persists only a
hash of the owner token, a monotonically increasing owner fence, lease expiry,
execution mode, and terminal publication reference. `PURE` claims may be taken
over after expiry under a higher fence; a stale owner cannot publish.
`IDEMPOTENT_EXTERNAL` claims with unknown delivery must first enter adapter
recovery. If recovery cannot prove a published result, the claim is explicitly
`ABANDONED` and cannot later be blindly re-executed.

The winning owner publishes one content-addressed
`AcquisitionExecutionPublication` before any EvidencePack mutation. It binds the
full request, execution manifest, ToolResult, every typed output object,
execution mode, idempotency key, owner digest, and fence. A crash after this
publication is recovered from SQLite without crossing the tool boundary again.
Claim and publication documents are independently canonicalized and index
validated; mutable owner secrets are never projected.

The public offline executor is also manifest-pinned. If an authored acquisition
fixture exists, the RunManifest must contain the exact software component
document `m4-controlled-fake-acquisition -> {package=labcourt,
version=0.1.0, license_id=Proprietary}`. Each ToolExecutionManifest binds the
SHA-256 of that canonical component document. A missing or different component
fails with `ACQUISITION_COMPONENT_UNPINNED` before any M4 acquisition authority
is created. The fixture bundle content address and command report both include
the authored `acquisition_fixture_count`; fixture outputs remain simulated
claims and are not evaluation evidence.

The new pack is an append-only semantic successor: version is exactly `v + 1`,
the Case pack-history sequence retains its prefix, every prior evidence object
remains present and byte-equivalent, tool outputs and result are added with exact
creation closure, and the old pack is never mutated. Stable-sorted collections
inside the new pack do not require the old tuple to be a literal prefix.

Under the frozen EvidencePack contract, `OTHER_CAMERA_SAME_TIME` is
metadata-only context. Its typed target-camera FrameRefs may appear in the
ToolResult closure, but they are not inserted into event key-frame or crop
collections, are not placed in role media, and cannot support a visual semantic
claim. The role whitelist may expose the ToolResult itself, not foreign-camera
pixels. Useful cross-camera visual adjudication requires a future explicit
privacy-safe acquired-media contract and is outside M4. The action never
performs identity matching, face recognition, or cross-camera ReID.

Similarly, a `REQUEST_MORE_FRAMES` result does not make pixels citable merely by
adding FrameRefs. Visual use requires a later explicit crop-producing action, or
an executor result whose typed receipt explicitly includes privacy-safe crops;
the executor may not silently add unrequested visual evidence.
`REDETECT_HIGH_RES` produces typed detections under a new model manifest and
never rewrites an earlier detection or decides the case.

Pack publication and the latest Case/EvidencePack binding, hearing round, case
revision, audit entry, and acquisition receipt commit in one M4 transaction. An
append-only adjacent derivation row additionally binds the exact predecessor and
successor IDs/versions to the request, completed execution publication,
execution manifest, ToolResult, receipt, and creating audit sequence. Reload and
read-only validation reject a missing derivation, a cross-run document, a wrong
predecessor, a version gap, or a forked history. The transaction does not call
the M2 transition that returns the case to `EVIDENCE_READY`.

### Verdict and deterministic review

Only a terminal judge output can be mapped to the frozen `Verdict`. The builder
copies the exact prosecution arguments, defense arguments, one judge response
per defense argument, controlled precedent applications, acquisition log,
objective claims, observation sufficiency, and all role response references.
Every persisted terminal proposal mapped to a Verdict—passed, reworked, or
finally rejected—has exactly one `HearingVerdictBinding`. No hearing-origin
Verdict may exist without a binding, and no binding may target more than one
Verdict. This proves the exact record/output/verdict relationship without
changing the verdict wire format.

The existing L5 gate remains independent and deterministic. A failed review
appends the verdict and review, moves the case to `REWORK_REQUIRED`, and either
starts the next bounded rework cycle or moves to human review after the final
allowed failure. A passed latest review moves the case to
`READY_FOR_ALERT_POLICY`. M4 does not send an alert.

Every direct M4 transition to `HUMAN_REVIEW` requires a content-addressed
`HearingHumanReviewReceipt`. Its controlled reason is one of
`ACQUISITION_LIMIT_EXHAUSTED`, `REWORK_LIMIT_EXHAUSTED`,
`HEARING_BUDGET_EXHAUSTED`, `EVIDENCE_UNAVAILABLE`,
`ACQUISITION_UNRECOVERABLE`, or `HEARING_BACKLOG_EXHAUSTED`. The final Case
timeline entry has `action=CASE_STATE_CHANGED`, `stage=HEARING`,
`object_ref=receipt_id`, and an exact bounded detail matrix containing the
reason, hearing ID, and cycle index. SQLite and read-only validation bind that
receipt bidirectionally to the Case, hearing, current pack, and optional
review/backlog/acquisition authority.

### Recovery and inspection

Provider-free maintenance can converge an exact journaled M4 raw response and
acknowledge it, but it cannot parse output, execute acquisition, resume a role,
advance a case, or reset a budget. Business retry requires the exact hearing
backlog lease and checkpoint. Read-only validation reconstructs the M4 root
graph from one SQLite snapshot and verifies both directions of response, role,
round, acquisition, pack, verdict-binding, lease-completion, audit, and current
case references. It also reopens every EvidencePack crop and independently
published acquired crop through the physical PNG verifier, then matches every
canonical authority document against the complete content-addressed M4 current
projection generation.

The frozen M2/M3 validator can report expected findings after a legal M4
successor becomes current. M4 does not ignore that embedded report. It
supersedes only three findings that the valid M4 graph proves directly: the old
M2 current-pointer authority mismatch, an M4-owned response reported as
unreferenced by M3, and an M4-owned hearing Verdict reported with the old M3
binding mismatch. Supersession is allowed only after M4 authority scanning and
physical media validation have no failures. Every other embedded M2/M3 issue is
translated into a typed `EMBEDDED_M3_DEFECT` and remains gating.

## Consequences

- A hearing is resumable at a role boundary without duplicating durable work.
- The two bounded loops cannot accidentally expand into an unbounded nested
  loop.
- Tool requests remain data, not executable instructions.
- Typed claims, monotonic fences, and pre-pack execution publications make the
  acquisition side-effect boundary recoverable without trusting process memory.
- New evidence cannot erase or rewrite earlier evidence.
- Adjacent derivation records make every M4 pack successor independently
  reconstructible and reject cross-run, skipped, or forked lineage.
- A final verdict exposes the complete adversarial and acquisition provenance
  while retaining the frozen M3 contract.
- M4 can be exercised fully offline with independent role fakes and controlled
  acquisition fixtures; no accuracy, cost, latency, or throughput claim follows
  from those fixtures.
