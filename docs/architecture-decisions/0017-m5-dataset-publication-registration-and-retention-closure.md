# ADR 0017: M5 dataset publication, registration, and retention closure

- Status: Accepted
- Date: 2026-08-03
- Milestone: M5
- Depends on: ADR 0008, ADR 0009, ADR 0015, ADR 0016
- Historical replay amended by: ADR 0018

## Context

An M5 training dataset spans two authorities that cannot participate in one
transaction: immutable bytes in the secure workspace and canonical registration,
retention, and audit rows in SQLite. Trusting a self-consistent export report would
not prove that it was built from the complete durable label inventory, that its
Crop receipts still identify current evidence, or that either the source Crop
files or the published dataset file exist with the claimed bytes.

Publishing SQLite authority before the file can leave a committed record pointing
to missing content. Trying to compensate for a failed database commit by deleting
an already-published file would weaken no-overwrite publication and introduce a
second destructive failure path.

## Decision

### Registration contract and physical verification

Dataset registration accepts both a validated `DatasetExportReport` and the exact
`content: bytes`. A report or content hash alone is insufficient.

The composition root must inject two narrow trusted verifiers into the repository:

- `M5TrainingCropVerifier`, implemented by `StoredPngVerifier`, re-opens every
  selected current Crop and returns its real current-media verification matrix.
  The repository never synthesizes actual hashes, dimensions, or sizes from Crop
  metadata.
- `M5DatasetArtifactVerifier`, implemented by
  `SecureDatasetArtifactVerifier`, re-opens the report's published relative path
  through `SecureWorkspace` and requires the expected SHA-256, size, and exact
  supplied bytes.

Missing verifier authority, a missing file, unsafe path, changed bytes, invalid
media, pixel mismatch, size mismatch, or hash mismatch fails with a typed error
before any dataset registration write.

### Durable rebuild is the registration authority

On first registration, inside the same `BEGIN IMMEDIATE` transaction, the
repository performs a bounded complete scan of the run's durable training-label
inventory and its strict-causal ledger. It validates each label against the pinned
run manifest, loads every selected label's current Case and latest complete
evidence pack, locates the referenced current Crop, and attaches the real physical
verification result.

The repository then deterministically rebuilds the export command, COCO bytes,
selection and quarantine partitions, image and category inventories, counts,
Crop authority receipts, content size, and content SHA-256. The rebuilt report
and bytes must equal the proposed report and content exactly. A forged but
internally self-consistent report, an omitted pre-cut label, a stale Case/Crop, or
a changed pre-cut authority is rejected. Historical replay uses the causal cut and
normalized authorities defined by ADR 0018; a legal post-cut append does not
invalidate the registered dataset.

### Atomic SQLite closure

After physical verification and exact rebuild, one SQLite transaction inserts:

1. the fixed registration snapshot and normalized historical Crop rows;
2. the causal registration marker immediately after the captured cut;
3. the immutable `dataset_artifacts` row;
4. one active, dataset-owned `GOLD_SET` retention hold for every exported Crop;
5. each hold's `RETENTION_HOLD_CREATED` audit entry; and
6. each hold-to-audit link.

The hold IDs are deterministic consequences of the export report. Their policy is
`m5-gold-set-retention-v1` with retention period
`UNTIL_EXPLICIT_RELEASE`. Any constraint failure, concurrent change, verifier
failure, or injected fault rolls back the dataset row, every hold and link, every
new audit entry, and the run audit head together.

An exact replay first validates the complete causal ledger, resolves only the
registered prefix and historical Case/EvidencePack/Crop authorities, and repeats
physical verification and the deterministic rebuild. It then requires the one
canonical dataset row and the complete exact inventory of active holds, including
canonical documents and indexes and valid creation audit/link closure. A missing,
released, changed, or extra dataset-owned hold fails closed. A successful replay
returns the existing artifact and appends no audit entry.

### Cross-resource publication order and recovery

The filesystem and SQLite cannot provide a shared atomic commit. M5 therefore
uses an intentionally asymmetric order:

1. build deterministic content;
2. publish it through the secure create-new/no-overwrite workspace boundary;
3. re-open and verify the published bytes; and
4. register the dataset and retention closure in SQLite.

If publication fails or conflicts, no database authority is written. If
registration fails after publication, the exact immutable file may remain
unregistered. This is a recoverable orphan: retry with the same report and bytes
reuses the identical no-overwrite file and can complete registration. The design
does not leave a committed dataset authority pointing to a file that was never
published.

The read-only artifact validator subsequently compares physical dataset presence
and bytes with SQLite dataset and retention authority. It reports missing,
unregistered, changed, or otherwise divergent physical/authority state without
mutating the authoritative workspace or database; any repair remains a separate
controlled operation.

## Consequences

- Dataset registration is an evidence-derived authority, not acceptance of a
  caller's report assertions.
- Exported reviewed Crops cannot lose their dataset retention protection through
  a partial commit or permissive replay.
- A database failure may leave an immutable unregistered file, but cannot leave a
  partial dataset/hold/audit closure or a database reference to unpublished
  content.
- Registration performs repeated local integrity reads and deterministic rebuilds.
  This ADR makes no claim about training quality, accuracy, latency, throughput,
  or cost.
