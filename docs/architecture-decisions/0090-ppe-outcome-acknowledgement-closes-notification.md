# ADR 0090: PPE outcome acknowledgement closes the notification

## Decision

After simulated outcome delivery, the student can explicitly acknowledge the
result through a separate command. The existing notification lifecycle commits
`DELIVERED -> ACKNOWLEDGED` under the persisted student actor authority.

Acknowledgement closes the notification loop only. The terminal
`APPEAL_RESOLVED` Case remains unchanged and no disciplinary authority is
created.

## Consequences

- Case closure and notification closure are independently visible in audit.
- Exact acknowledgement retries return the same commit.
- Default startup never acknowledges on behalf of the student.
