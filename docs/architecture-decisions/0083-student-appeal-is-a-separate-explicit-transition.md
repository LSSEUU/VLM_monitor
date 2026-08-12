# ADR 0083: student appeal is a separate explicit transition

## Status

Accepted for the offline personal Demo.

## Context

The PPE candidate now supports explicit safety review. A student-facing Demo needs an appeal path, but
reusing the safety token or combining confirmation and appeal would erase role separation and human
intent.

## Decision

The student appeal client resolves only the exact local PPE receipt, fetches current Case authority
using the student token, and submits the existing `SUBMIT_APPEAL` action with `SUBJECT_DISPUTE`. It
requires a separate explicit `APPLY` confirmation and writes the returned typed Case commit only to the
ignored local directory.

The persisted transition matrix remains authoritative: only a subject-matching student can appeal a
`CONFIRMED` or `RESOLVED` Case. A pending candidate, wrong subject, stale version, wrong role, or missing
confirmation fails closed. The one-click start path does not invoke the appeal command.

## Consequences

The Demo can show safety review followed by student-controlled due process without granting the student
confirmation, rejection, resolution, or appeal-resolution powers. Submitting an appeal does not
automatically overturn, close, notify, or discipline anyone.
