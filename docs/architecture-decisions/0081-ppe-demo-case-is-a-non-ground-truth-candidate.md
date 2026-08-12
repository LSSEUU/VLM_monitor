# ADR 0081: PPE Demo Case is a non-ground-truth candidate

## Status

Accepted for the offline personal Demo.

## Context

The authorized recorded media is now playable, but its filename and availability do not prove that a
person lacks goggles. A useful product Demo still needs a student-scoped PPE Case that exercises human
verification and later explanation/appeal paths without inventing visual facts.

## Decision

An explicit idempotent command creates one `GENERAL/PENDING_VERIFICATION` Case whose trigger is the
content-addressed recorded-media binding represented as a `VIDEO_EVENT`. The fixed scenario proposition
is `GOGGLES_MISSING_CANDIDATE`; the receipt states that media content was not verified, the filename was
not evidence, the machine weak label is not ground truth, and no model, GPU, or network was used.

The Case is assigned to the persisted `student-demo` subject and the simulated recorded-camera source.
The existing create-command contract enforces human verification and forbids direct disciplinary
action. The command does not confirm, reject, notify, resolve, or discipline the subject.

## Consequences

Safety officers can demonstrate review of a realistic PPE candidate while students can discover their
own Case through the existing role-scoped API. The scenario remains an advisory simulation, not a claim
about the actual video or a validated perception result.
