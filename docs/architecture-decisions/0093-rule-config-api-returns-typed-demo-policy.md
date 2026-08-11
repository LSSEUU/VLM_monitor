# ADR 0093: Rule config API returns typed Demo policy

## Decision

`GET /api/m8/rules` returns the exact typed
`M8SensorRiskPolicyAuthorityV1` used by the offline smoke Demo. The policy is
rebuilt from the same source catalog and pinned manifests as bootstrap, not
parsed from knowledge documents or free text.

Leaders and safety officers can read it. This slice is deliberately read-only;
only safety already holds `MANAGE_RULES`, and a future mutation endpoint must
add persisted revision/optimistic-concurrency authority before enabling edits.

## Consequences

- The rule screen can show threshold, risk, auto-case and deadline semantics.
- Ordinary documents still cannot silently become operational rules.
- Operations and students cannot read the full rule configuration.
