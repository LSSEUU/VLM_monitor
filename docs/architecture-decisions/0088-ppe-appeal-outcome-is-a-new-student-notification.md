# ADR 0088: PPE appeal outcome is a new student notification

## Decision

After `APPEAL_RESOLVED`, the personal Demo creates a new typed student outcome
notification instead of mutating the earlier confirmation card. Its route
receipt binds the exact terminal Case version/hash and the closed appeal
resolution. The target is a revisioned acknowledgement-only local target, so
the final card cannot invite a second explanation or appeal.

Routing stops at `QUEUED`, remains offline, and cannot transition the Case or
create disciplinary authority.

## Consequences

- The student sees a separate immutable result message in notification history.
- The original response audit remains intact and is not overwritten.
- Delivery remains a subsequent explicit action and is not claimed by routing.
