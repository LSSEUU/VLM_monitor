# ADR 0011: M3 durable response recovery, bounded retry, and SQLite sidecar lifecycle

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0010 fixes the semantic order of a model call, but a real process can stop at
every boundary in that order. In particular, it can stop after receiving provider
bytes, while publishing those bytes, after publication but before the SQLite call
receipt, or while a backlog worker owns a lease. Startup recovery can also race a
live worker, and SQLite WAL sidecars can enter a transient delete-pending state on
Windows.

Recovery must not call a provider, parse model content, advance a case, charge
usage twice, or decide from an incomplete directory scan. Retry must resume the
exact failed stage rather than create another case. File inspection must remain
bounded even when the workspace is hostile or unexpectedly large.

## Decision

### Journaled raw-response publication

`SecureModelResponseStore` publishes one response through an owner-only staging
file and a content-addressed publication journal. The journal binds the complete
request identity to the exact `VLMResponse`, response ID, raw-body hash, byte
count, and final relative locator. Publication is idempotent only when every
bound field and byte agrees.

The final raw body is authoritative only at
`<run_id>/model_responses/<response_id>.json`. A journal is retained until the
final file is verified and the immutable SQLite response receipt is durable. An
incomplete publication remains recoverable; it is not converted prematurely
into a parse failure or another provider call.

Every recovery read supplies the exact expected size and hash. The maintenance
boundary has independent per-response and aggregate raw-byte budgets in addition
to its item-count limit. A file that grows, changes identity, becomes linked, or
exceeds either byte budget fails closed.

### Provider-free startup recovery

Recovery is a separate application path with no VLM client and no business-state
writer. It first performs a bounded, complete claim scan. An incomplete or
over-budget scan cannot authorize any mutation.

The claim budget is a per-run total, not a SQL page size. SQLite establishes one
read snapshot, counts the run's claims, and walks that same snapshot in stable
`request_id` keyset pages. Recovery starts only after every claim within the
configured total limit has been reconstructed and the complete inventory is
free of anomalies. If the count exceeds the limit, the bounded prefix is
reported as incomplete and nothing is mutated. The CLI exposes this claim-total
limit independently from the smaller filesystem/artifact limit. New claims are
atomically refused once the run reaches the same hard recovery capacity, so a
valid run cannot grow into a state that the maintenance path is forbidden to
inventory.

For an expired call claim, recovery first restores and verifies the exact
journaled final response, then completes the response receipt, cache, and claim
in one SQLite transaction using compare-and-swap on the observed lease and
takeover count. The recovery repository capability never returns a new owner or
an `ACQUIRED` state, so it cannot authorize another provider send even if it is
miswired in the future. A claim with an unexpired lease is deferred. An expired
claim without a publication journal is also deferred but makes the report
require attention; it is never reported as successful recovery and never
triggers an automatic duplicate call.

After ordinary expired-claim handling, recovery acquires a SQLite
`BEGIN IMMEDIATE` writer fence and performs a second claim scan. While that fence
is held, repository writes through the recovery composition are prohibited.
The second scan repeats the complete keyset inventory inside the writer-fenced
snapshot. Only this second, complete view may authorize reverse-reference checks and
physical cleanup. This prevents a live writer from creating a reference after
the scan but before quarantine.

Recovery may:

- finish or acknowledge an exact journaled publication;
- verify an already durable, exactly referenced response;
- remove an exact obsolete journal after durable acknowledgement; or
- quarantine an old, unreferenced physical candidate under the private
  `.quarantine` hierarchy.

It may not synthesize a response receipt, parse a response, advance a case, write
usage, or delete an anomalous or ambiguously referenced artifact. Every item has
a typed reason and disposition. Any anomaly, incomplete scan, expired claim
without a journal, or budget failure makes the aggregate report fail closed.

### Single-item backlog retry

One invocation reclaims a bounded number of expired leases and leases at most one
`SCREENING` item. Stage filtering is part of the atomic SQLite lease query, so an
M3 worker cannot accidentally own future `HEARING` work.

The backlog item binds the original run, case, stage-input hash, retry generation,
and current case revision. Lease acquisition increments the bounded attempt
count and therefore consumes that attempt even if the worker stops before it can
publish a typed processing outcome. An expired lease never refunds the attempt.
Recovery records a `WORKER_LEASE_EXPIRED` failure with no model-response or
parse-failure claims, then atomically writes the next backlog version, Case
revision, audit entry, and completion receipt under the expired lease identity.
If budget remains the item returns to `PENDING` with its attempt count preserved;
otherwise it becomes `EXHAUSTED` and the Case moves to `HUMAN_REVIEW`. Completion,
exhaustion, screening commit, verdict/review commit, usage publication, and every
backlog completion receipt use the exact lease identity and expected revision as
compare-and-swap authority.

Retry reuses a valid durable response or cache entry before making another call.
One complete proof containing both failed strict parses is the only condition
that advances the structure-repair generation. Provider interruption does not
advance it. Persisted model responses keep their exact response references and
usage is committed once. A successful retry atomically completes the backlog
item. A typed processing interruption returns to `PENDING` only when budget
remains; an unknown worker stop is represented solely by the lease-expiry
recovery receipt above. Neither path can exceed the configured lease-acquisition
count.

An ordinary model-call claim never takes over an expired active claim whose
delivery is unknown. It returns `EXPIRED_REQUIRES_RECOVERY` without changing the
owner, expiry, or takeover count, and no provider is called. The maintenance-only
completion primitive can only converge an exact, physically reverified response
into a terminal claim; no recovery port exposes a claim-takeover primitive.

Claim recovery, artifact recovery, and the writer fence share only an opaque
composition identity. Coordinators expose that capability-free token for the
three-way wiring check; they never expose the underlying `SQLiteM3Repository`,
so maintenance callers cannot reach `claim_model_call`, aggregate commits, or
any other provider/business authority through the recovery surface.

After exact SQLite completion/cache convergence and a second physical raw-file
verification, acknowledgement is idempotent. If another maintenance process
has already removed that exact journal, `RESPONSE_NOT_FOUND` at the final
acknowledgement step is treated as the same terminal success. This exception is
not applied before database/raw verification; response conflicts, changed
bindings, and every other store failure remain typed anomalies.

A provider failure can authorize a later business retry only when the adapter
proves `DEFINITELY_NOT_SENT` or `COMPLETED`. Its full request, claim epoch,
delivery certainty, failure code, and backlog closure are written as an
append-only failure authority in the same transaction as the Case, audit, and
backlog transition. Retry must present the exact current backlog lease. Worker
or lease provenance never changes generation-zero request identity; only the
strict two-parse proof advances the semantic retry generation.

Artifact validation checks this in both directions: every completion receipt
must bind the immediately preceding `LEASED` version, and every historical exit
from `LEASED` must have exactly one completion receipt. A currently active leased
head does not require a receipt until it exits the lease.

The lease duration must cover the stale-call-claim wait, at most two configured
model calls, and commit margin. Configuration bounds make that minimum
constructible within the four-hour lease ceiling. A caller cannot select a
shorter lease.

### Windows WAL/SHM handles

SQLite main, WAL, and SHM files remain a single authority set. Reparse points,
non-regular files, and multiply linked sidecars are rejected.

On Windows, WAL/SHM cleanup can leave a successfully opened handle with link
count zero or can retire a pathname between handle open and final-path
verification. Such a handle is never accepted as the current sidecar. The
authority closes it and performs a bounded reopen of the exact pathname. A
replacement is accepted only after its own identity, link count, attributes, and
final path pass all checks. Hard links, a link-count-one path escape, unsafe
attributes, and handle-close failure remain hard errors; they are not normalized
as ordinary retirement.

## Residual boundaries

A process can die after a provider has returned bytes but before the publication
journal reaches durable storage. Without provider-side idempotency there is no
local proof of that response, so recovery deliberately reports an expired
claim-without-journal for attention instead of guessing.

A new worker cannot repeat an external call merely because an unknown active
claim expired. A previously authorized worker can still be suspended after claim
acquisition and resume after its backlog lease expires, transmitting the one call
it had already been authorized to make. The still-current model-call owner may
durably converge that exact response and cache receipt after its backlog lease
expires; doing so prevents another provider send and does not itself change the
Case or usage. Exact backlog lease and Case-revision compare-and-swap prevent the
stale worker from advancing business state or charging usage. They cannot cancel
an already transmitted provider request. Production deployment should combine
this protocol with provider idempotency keys where available.

Bounded Windows sidecar reopen handles the observed delete-pending lifecycle; it
does not treat arbitrary continuous namespace churn as recoverable. Exhausting
the reopen budget is a typed integrity failure.

## Consequences

- Startup recovery is offline, bounded, repeatable, and cannot adjudicate a case.
- A durable response is reused across process restart without duplicate usage.
- A partial scan or ambiguous artifact produces visible attention rather than a
  reassuring success.
- Backlog retry has one durable owner and one atomic terminal transition.
- Future M4 `HEARING` workers must use their own stage-specific retry processor.
- Windows WAL/SHM retirement no longer creates an intermittent false path escape,
  while link and reparse protections remain fail closed.
