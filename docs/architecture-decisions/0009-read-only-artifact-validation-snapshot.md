# ADR 0009: Read-only artifact-validation SQLite snapshots

- Status: Accepted
- Date: 2026-07-27

## Decision

`labcourt artifacts validate` must not open the authoritative SQLite database with
SQLite itself. On WAL databases, SQLite can update read marks in the authoritative
`-shm` file even when the connection URI uses `mode=ro` and `PRAGMA query_only`.
That observable write violates the validator's read-only contract.

The validator instead treats the main database and the optional `-wal` and `-shm`
sidecars as one global source set. It records the complete presence set, rejects
links, reparse points and non-regular or multiply-linked files, opens every member
read-only, and records handle identity, size, modification time and SHA-256. It then
copies every member from those already-open handles into an owner-only temporary
directory. After all copies complete, it rechecks the entire presence set, every
path and handle identity, and every SHA-256. A sidecar appearing or disappearing,
or any identity, byte or timestamp change, fails with a typed boundary error. The
same global check runs after SQLite backup and when validation releases the
snapshot.

Only the private raw copy is opened by SQLite. SQLite's backup API interprets the
copied database and WAL and produces the clean private snapshot consumed by the
repository. The raw copy and backup output use owner-only directories and files and
are removed after validation. A rollback-journal source is rejected rather than
being incompletely interpreted.

## Residual boundary

This design does not claim that the authoritative database is completely
handle-anchored. Python's standard SQLite binding opens the private copy by path,
and opening the authoritative path before obtaining the read handles retains a
path-open race. The global pre/post identity and hash checks detect ordinary
replacement and concurrent mutation, but a same-privilege attacker capable of a
perfect identity/hash ABA between checks remains a residual risk. Removing that
boundary requires a custom SQLite VFS or an operating-system snapshot facility and
is outside M2. The CLI and report therefore describe a read-only, globally checked
copy-and-backup boundary, not an absolute handle-anchored SQLite authority view.

## Consequences

- Artifact validation never intentionally changes authoritative main/WAL/SHM
  directory entries, bytes, sizes or modification times.
- Live writes during snapshot creation or validation produce a typed boundary
  failure instead of a mixed snapshot.
- Snapshot creation performs multiple streaming reads of the source set, trading
  I/O for deterministic no-write behavior and bounded memory.
