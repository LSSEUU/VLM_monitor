# ADR 0018: M5 strict-causal training dataset snapshots

- Status: Accepted
- Date: 2026-08-03
- Milestone: M5
- Depends on: ADR 0015, ADR 0016, ADR 0017
- Amends: ADR 0017 historical replay semantics

## Context

ADR 0017 correctly required first registration to prove that a dataset was built
from the complete durable training-label inventory. Its original replay rule,
however, repeated that proof against the *current* complete inventory and the
current Case head. A legal label append or later Case revision could therefore
make an already registered, byte-identical dataset fail replay.

That behavior violates `STRICT_CAUSAL`: facts created after an authority was
committed must not rewrite whether that past authority was valid. At the same
time, simply ignoring the current database would hide deletion, source
substitution, chain gaps, or a forged historical Crop.

The frozen `DatasetArtifact`, `DatasetExportReport`, and
`CocoDatasetExportCommand` identities cannot be changed. The solution must be
additive, bounded, offline by default, and must not infer history from timestamps,
SQLite row order, or mutable Case heads.

## Decision

### Per-run training causal ledger

M5 adds an append-only, per-run hash chain with two event kinds:

- `TRAINING_LABEL_APPENDED` binds one exact `M5TrainingLabelAuthority`, including
  its canonical wrapper document hash; and
- `DATASET_REGISTRATION_COMMITTED` binds one exact registration snapshot.

Sequence numbers are contiguous, every predecessor hash is exact, source
identities are unique, and all events remain in the pinned run manifest scope.
Every label and its causal event are written in the same `BEGIN IMMEDIATE`
transaction. A durable label without exactly one matching event, or an event
without its label authority, is an integrity failure.

### Registration cut and normalized snapshot

First registration observes the verified ledger head as a causal cut. The export
report must account for every label-append event at or before that cut, partitioned
exactly into exported and quarantined labels.

The durable registration closure is normalized:

1. a fixed-size `M5DatasetRegistrationSnapshotAuthority` stores the report hash,
   causal watermark, label count/root, Crop count/root, and pinned manifest/rule/
   detector identities;
2. label snapshot receipts are deterministically derived from the immutable label
   authorities and their causal events rather than copied into one unbounded row;
3. one `M5DatasetCropSnapshotAuthority` per exported Crop stores the exact
   `TrainingCropAuthority`, Case revision and document hash, and EvidencePack
   identity/version/document hash; and
4. the dataset registration event must be exactly `cut.sequence + 1` with the cut
   hash as its predecessor.

The snapshot header, normalized Crop rows, registration marker, dataset artifact,
retention holds, audit rows, and hold links commit atomically. Deferred foreign
keys close the intentional snapshot/artifact cycle without weakening append-only
triggers.

### Historical replay

Replay still validates the complete current causal ledger and every current label
source. It then reconstructs the registered dataset from only the label events at
or before the stored cut and the stored historical Crop authorities.

Consequently:

- a legal event after the cut is validated globally but excluded from the old
  dataset rebuild;
- a missing, reordered, forged, or source-mismatched event at any point fails;
- a missing or changed historical Case/EvidencePack/Crop document fails;
- current Crop bytes are re-opened and physically verified against the historical
  Crop authority; and
- a later current Case revision is not substituted for the registered Case cut.

The read-only validator independently performs the same ledger bijection,
snapshot/root/marker closure, exact historical document checks, physical Crop
verification, and deterministic dataset rebuild.

### Same-command service replay

The export command identity remains unchanged. Before building from current
inventory, the service looks up an existing report by `(run_id, command_id)`. If
present, it re-opens the exact published bytes and asks the repository to perform
the full historical replay. It does not overwrite the file or create new
registration state.

To intentionally export a new inventory, the caller chooses a new output path,
which creates a new command identity and a new causal registration.

### No inferred backfill

M5 is not frozen yet, so migration `0009` is extended in place. No production
history is guessed or backfilled. A database containing labels without causal
events fails closed and must be migrated through an explicit, separately
authorized process if such data ever exists.

## Rejected alternatives

- **Rebuild old datasets from current inventory.** This lets future valid facts
  invalidate past authority.
- **Use timestamps, row IDs, or label lexical order as the cut.** None is a causal
  authority and all permit ambiguous history.
- **Store full label and Crop arrays in the snapshot header.** This creates an
  oversized authority row and weakens bounded preflight.
- **Stop validating the global tail.** That would let corruption outside one old
  dataset remain hidden.
- **Change frozen dataset/report identities.** The required semantics are additive
  and do not justify a breaking wire change.

## Consequences

- Registered datasets remain stable under legal future labels and Case revisions,
  while deletion and historical substitution still fail closed.
- Registration and replay perform additional bounded local reads and hashes.
- The ledger supports up to 100,000 events per run; label and Crop snapshot
  inventories retain the existing 10,000-item export bound.
- Projection and validation gain three authority kinds and typed causal/snapshot
  failure reasons.
- This decision makes no claim about model quality, accuracy, latency, throughput,
  or cost.
