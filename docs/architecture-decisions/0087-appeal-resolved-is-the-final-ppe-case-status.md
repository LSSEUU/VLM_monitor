# ADR 0087: APPEAL_RESOLVED is the final PPE Case status

## Decision

The personal Demo uses the existing frozen `RESOLVE_APPEAL` transition for the
safety officer's explicit appeal decision. It requires an exact current
`APPEALED` PPE Case, the safety-officer bearer authority, a closed
`UPHELD | OVERTURNED` resolution, a matching reason code, and explicit human
confirmation.

The resulting `APPEAL_RESOLVED` status is the terminal closed status for this
appeal path. We do not add a synthetic second `RESOLVE` transition because the
frozen Case matrix intentionally permits `RESOLVE` only from `CONFIRMED`.

## Consequences

- Appeal handling and final closure are one audited human-controlled transition.
- The transition does not directly authorize disciplinary action.
- Default startup cannot resolve an appeal, and the client performs no retry.
