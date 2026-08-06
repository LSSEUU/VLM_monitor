# ADR 0015: M5 transactional side-effect authority

- Status: Accepted
- Date: 2026-08-02

## Context

M0 through M4 deliberately stop at `READY_FOR_ALERT_POLICY` or a typed human
boundary. M5 introduces the first adjudication side effects: closing a Case,
queuing an alert, publishing precedents, accepting an appeal, rescinding an old
outcome, and exporting human-authorized training labels. A crash or replay must
not close a Case without its outbox row, deliver one alert twice, activate an
appealed automatic precedent, rewrite a historical citation, or apply only part
of an overturn.

The existing `Precedent`, `AlertDecision`, `Appeal`, `TrainingLabel`,
`DatasetArtifact`, and `Case` contracts were exported before M5 and are used by
frozen milestones. Adding persistence fences or operational metadata directly
to those wire documents would silently change earlier identities.

## Decision

### Additive authority roots

M5 keeps the frozen documents as semantic snapshots and adds independent,
content-addressed wrappers for queries and embedding receipts, precedent
versions and citations, alert policy inputs and close intents, outbox leases and
delivery attempts, appeal versions and resolution effects, verdict/alert
rescissions, affected citations, and dataset export receipts.

Every wrapper binds the run manifest and the exact upstream Case revision,
Verdict, procedural review, policy/config version, reviewer or dispatcher fence,
and any predecessor version. SQLite is authoritative; JSON remains a rebuildable
projection.

### Atomic business boundaries

Closing a Case and inserting its alert outbox entry is one `BEGIN IMMEDIATE`
transaction. Resolving an appeal is another: the Case successor, terminal appeal
version, rescission authorities, precedent transitions, affected-citation
snapshot, and training labels either all commit or all roll back. The repository
validates current heads and immutable documents inside the transaction rather
than relying on an application-layer read-then-write check.

### At-least-once delivery with an exactly identified effect

An outbox worker leases one current entry under an owner digest and monotonic
fence. A channel call always receives `idempotency_key == alert_id`. Attempts are
append-only. One accepted receipt closes the outbox item; later replay returns
that receipt and never calls the channel again. Unknown delivery remains a
recovery state and is not blindly retried unless the channel's idempotency
contract can make the effect safe.

### Precedent anti-contamination

Automatic precedents are provisional until the configured frame-independent
calendar delay has elapsed and the source Case has no appeal. Retrieval is an
exact, bounded local calculation. Status, rule, evidence class, source weight,
embedding manifests, candidate inventory and scores are persisted so a model
cannot invent or silently reorder a precedent.

Conflict status is versioned. Conflict governance first computes the complete
opposite-direction graph for one budgeted ACTIVE-head snapshot; it never commits
pair-by-pair. A node with any higher-priority neighbour is invalidated, otherwise
a node on any equal-priority edge enters conflict, otherwise it remains active.
The governing neighbour is selected by descending priority then ascending
precedent ID. One content-addressed batch authority and receipt bind the policy,
config, complete candidate authority inventory, every qualified edge, and every
node result. Revocation returns immutable historical citations but never mutates
the Cases that made them.

### Human authority for feedback

An overturn may create `APPEAL_CONFIRMED` labels only from an explicit human
resolution and evidence already in the Case closure. Automatic labels remain
weak. Default export accepts only `HUMAN_CONFIRMED` and `APPEAL_CONFIRMED`; all
others are reported as quarantined.

## Consequences

- Migration 0009 adds strict M5 tables and triggers without changing migrations
  0001 through 0008.
- M3/M4 schemas and semantic hashes remain stable.
- More rows are written per close or appeal, but every externally meaningful
  side effect has a replayable authority and a transactional failure boundary.
- M6 can replay policy, precedent and appeal decisions from immutable roots
  without contacting a model, alert channel, or training service.
