# ADR 0086: PPE student reply is a separate authority

## Decision

The personal Demo accepts a student notification reply only after simulated
delivery through an explicit `ppe-notification-reply` command. Reply kind is the
closed `EXPLANATION | APPEAL_REQUEST` enum. The exact bounded UTF-8 text is kept
as a raw artifact and its SHA-256 is bound into the existing typed reply
authority and notification audit chain.

The reply changes only the notification to `RESPONDED`. It cannot transition a
Case or create disciplinary authority. An appeal request remains distinct from
the existing explicit student `SUBMIT_APPEAL` Case transition.

## Consequences

- Student intent is auditable without granting the message channel Case power.
- Exact retries return the same commit; conflicting reply bytes fail closed.
- No network or model call occurs, and default startup does not submit replies.
