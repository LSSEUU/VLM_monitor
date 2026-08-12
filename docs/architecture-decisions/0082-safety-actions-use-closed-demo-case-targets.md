# ADR 0082: safety actions use closed Demo Case targets

## Status

Accepted for the offline personal Demo.

## Context

The safety action client originally resolved only the immutable bootstrap smoke Case. The additive PPE
candidate needs the same human-controlled transition path, but accepting arbitrary local documents or
silently changing the default target would make the Demo ambiguous.

## Decision

The action boundary uses a closed target enum: `EMERGENCY_SMOKE` or `PPE_CANDIDATE`. The first remains
the default and resolves the bootstrap receipt. The second resolves only the exact local PPE Case
receipt. The client then fetches current Case authority from the loopback API and submits one existing
typed transition with the safety token and explicit confirmation.

The Windows script asks for the target before the action and still requires the operator to type
`APPLY`. The one-click start path never invokes this command.

## Consequences

Safety officers can review either Demo Case without copying a case ID, while leader, operations, and
student roles gain no transition capability. This change selects an authority; it does not perform a
transition unless a human explicitly confirms it.
