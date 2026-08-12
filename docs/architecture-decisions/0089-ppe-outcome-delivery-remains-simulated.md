# ADR 0089: PPE outcome delivery remains simulated

## Decision

The final PPE appeal outcome has a separate explicit offline delivery command.
It consumes the exact typed outcome route receipt, verifies the terminal Case
and acknowledgement-only target, and commits `QUEUED -> SENT -> DELIVERED`
through the deterministic fake channel.

`DELIVERED` remains a local simulation claim with
`real_delivery_confirmed=false` and cannot transition the Case.

## Consequences

- Outcome routing and delivery remain independently auditable.
- A persisted `SENT` outcome can resume deterministically without another plan.
- Feishu delivery is not implied by this local receipt.
