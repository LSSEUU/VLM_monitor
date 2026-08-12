# ADR 0085: PPE student delivery is explicit and offline

## Decision

The personal Demo advances a routed PPE student card only through a separate
`ppe-notification-deliver` command. The command consumes the exact typed route
receipt, verifies the current Case, notification, target and source hashes, and
uses the deterministic offline channel to commit `QUEUED -> SENT -> DELIVERED`.

The resulting delivery receipt always records `real_delivery_confirmed=false`
and `case_transition_permitted=false`. It is evidence of the local simulated
channel only, not evidence that Feishu or a person received the message.

## Consequences

- Default startup remains offline and never performs delivery implicitly.
- A replay returns the same current commit; interruption at `SENT` can resume
  deterministically from persisted dispatch authority and raw card bytes.
- The command cannot change the PPE Case or create disciplinary authority.
