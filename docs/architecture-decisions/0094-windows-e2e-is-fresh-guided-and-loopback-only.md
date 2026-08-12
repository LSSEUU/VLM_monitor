# ADR 0094: Windows E2E is fresh, guided, and loopback-only

## Decision

`labcourt-demo-e2e.cmd` creates a fresh ignored run directory, assembles the
recorded-video PPE candidate, starts the API on loopback, and guides one
operator through every human-controlled transition. Each safety/student action
has its own `APPLY` prompt before the existing CLI receives `--confirmed`.

The script then verifies terminal Case state, both student notifications, user
permissions, typed rules, sensors and device health, and writes a local
`acceptance.json`. It never attempts Feishu delivery and stops its hidden API
helper in `finally`.

## Consequences

- Every Demo run is isolated; old terminal authority is never silently reused.
- One launcher covers the complete offline product story without weakening
  human confirmation semantics.
- A passed acceptance file is local Demo evidence, not a production benchmark.
