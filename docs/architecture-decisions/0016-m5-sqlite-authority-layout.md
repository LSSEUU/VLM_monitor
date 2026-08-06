# ADR 0016: M5 SQLite authority layout

- Status: accepted
- Date: 2026-08-02
- Milestone: M5
- Depends on: ADR 0015

## Context

M5 adds mutable-looking lifecycles (precedent activation/revocation, alert delivery,
and appeal review) to an authority that otherwise stores immutable documents.  A
single JSON blob per object would make status replacement, partial appeal effects,
or a duplicate successful alert delivery too easy.  A second `precedents.db` would
also split business truth from the run's existing `labcourt.sqlite3` database.

## Decision

`labcourt.sqlite3` remains the only M5 business authority.  Migration 0009 adds
append-only roots and derives current state from the greatest validated revision:

- `precedents`: one complete `M5PrecedentAuthority` per `(run_id,
  precedent_id, revision)`; revisions are contiguous and earlier documents are
  never updated.
- `precedent_embeddings`: immutable, content-addressed vectors referenced by a
  precedent authority.
- `precedent_citations`: immutable citation commits.  Citation counts are derived
  from these rows and must agree with the latest authority when materialized.
- `precedent_lifecycle_receipts`: immutable activation, conflict, and revocation
  receipts.  A lifecycle receipt and every resulting precedent revision commit in
  one transaction.
- `precedent_conflict_batches` and `precedent_conflict_batch_receipts`: immutable
  complete-graph authorities for production conflict reconciliation. They bind the
  full ACTIVE-head snapshot, policy/config, qualified edges, and one result for
  every candidate. The older two-node lifecycle receipt remains a compatibility
  boundary only and is not used by production reconciliation.
- `alerts`: one immutable `AlertPolicyAuthority` bound to the source Case revision,
  verdict, passed procedural review, policy/config hashes, and closing Case
  revision.
- `alert_cooldowns`: immutable frame-based cooldown writes.  The latest eligible
  row is selected only for the same tracker epoch and stream authority.
- `alert_outbox`: immutable outbox intent, inserted in the same transaction as the
  `READY_FOR_ALERT_POLICY -> CLOSED` Case revision and its audit entry.
- `alert_dispatch_attempts` and `alert_dispatch_receipts`: append-only delivery
  history.  Every attempt uses `idempotency_key = alert_id`; a partial unique index
  permits at most one successful receipt per outbox item while failed attempts may
  be retried.
- `appeals`: one complete `AppealVersionAuthority` per `(run_id, appeal_id,
  version)`.  Versions 1, 2, and 3 correspond exactly to `SUBMITTED`,
  `UNDER_REVIEW`, and a terminal decision.
- `appeal_resolution_receipts`: one immutable terminal side-effect intent.
- `verdict_rescissions` and `alert_rescissions`: append-only rescission facts;
  original verdict and alert rows remain unchanged.
- `training_labels`: immutable labels.  Their quality tier is indexed, but the
  canonical `TrainingLabel` document is authoritative.
- `dataset_artifacts`: immutable records of deterministic exported bytes.

The M5 repository is composed from focused precedent, alert/outbox, and
appeal/training mixins over the frozen M3 SQLite foundation.  Its connection guard
requires the complete 0009 object set.  The shared M2 reader recognizes M5 Case
transitions through an additive transition validator; it does not relax any M2-M4
transition rule.

## Transaction boundaries

1. Case close validates the exact current Case revision, latest verdict, passed L5
   review, manifest/config authority, and cooldown snapshot.  It appends the Case
   version, audit entry, alert authority, optional cooldown, and optional outbox in
   one `BEGIN IMMEDIATE` transaction.
2. Dispatch claim/attempt and receipt are separate short transactions.  A crash
   may cause another attempt, but never another idempotency key or second accepted
   authority receipt.
3. Appeal submit and review each append one appeal authority and one Case version.
4. Terminal appeal resolution appends the terminal authority and Case version plus
   all rescissions, precedent revisions/replacement, affected-citation report,
   and labels in one `BEGIN IMMEDIATE` transaction.  Any rejected insert rolls the
   whole transition back.
5. Dataset bytes are built before publication.  The file is published by a secure
   no-overwrite boundary, then its exact content hash is registered; replay with
   identical bytes returns the same artifact, while a collision fails closed.
6. Conflict reconciliation validates every current ACTIVE head under one
   `BEGIN IMMEDIATE`, recomputes the complete graph, and appends all successor
   authorities plus the batch authority and receipt atomically. Any changed head
   or injected fault leaves no partial conflict governance.

## Consequences

- Current status is a projection, not an overwrite; historical citations and
  decisions remain explainable after revocation or appeal.
- `precedents.db` may later be generated as a disposable compatibility projection,
  but it cannot become an input authority.
- SQL constraints provide coarse identity/append-only protection.  Pydantic
  validation and repository CAS checks still verify cross-document semantics.
- M5 artifact validation must traverse every canonical root and compare derived
  counts/statuses with the Case and audit chain rather than trusting indexed
  columns alone.
