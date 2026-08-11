# ADR 0064: Feishu personal-demo probe is not notification authority

## Status

Accepted for the Windows personal Demo only.

## Context

The full Feishu notification path correctly requires current commissioning evidence, two distinct human
activation confirmations, an allowlisted recipient binding, a queued notification and a one-shot call fence.
Those inputs are intentionally unavailable during a first enterprise-app connectivity check. Fabricating them
would make a convenient demo look like valid operational authority.

## Decision

Add a separate one-card connectivity probe. It accepts only the ignored local App ID, App Secret and test
recipient `open_id`, renders one fixed `PERSONAL DEMO · SIMULATED SAFETY EVENT` card, calls only the fixed
official Feishu token and message endpoints, and writes a typed receipt plus redacted token/message response
artifacts under `.labcourt-local`.

The probe has an offline check mode and a live mode that requires an explicit `SEND` confirmation in the
Windows wrapper. It has no case ID input, no database, no notification queue, no retry loop and no inbound
event handling. Its receipt permanently states that real delivery is unconfirmed and that notification, case
and disciplinary transitions are forbidden.

## Consequences

This provides a fast visible demo of enterprise-app connectivity without weakening or impersonating the full
activation chain. It cannot be used as a production adapter, notification receipt or commissioning artifact.
After connectivity is proven, product notification and reply demonstrations must return to the existing
activation-gated outbox/webhook path.
