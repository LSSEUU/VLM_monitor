# ADR 0091: User permission API is read-only current authority

## Decision

The personal Demo exposes `GET /api/m8/users` to leaders and safety officers.
It returns the existing typed current actor commit receipts, including role,
scope, capabilities, active state, revision and audit identity. The endpoint
does not accept client role/capability claims and exposes no mutation method.

Operations and students are forbidden from reading the campus-wide inventory.

## Consequences

- The product can render a permission matrix without duplicating authority.
- Bearer tokens and credential hashes are not part of the response.
- User/role administration remains outside this read-only Demo slice.
