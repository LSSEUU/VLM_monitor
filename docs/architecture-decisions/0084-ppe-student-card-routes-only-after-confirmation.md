# ADR 0084: PPE student card routes only after confirmation

## Status

Accepted for the offline personal Demo.

## Context

Students need a notification surface for the PPE workflow, but routing the machine weak label before a
safety officer confirms the Case would present an unverified candidate as an established finding.

## Decision

An explicit offline command resolves the exact PPE receipt and current Case authority. It can create a
`CASE_UPDATED/CASE_SUBJECT` notification only while the Case is `CONFIRMED`, targeted to the persisted
`student-demo` actor through `LOCAL_OFFLINE_FAKE`. The command creates and queues a deterministic card;
it does not dispatch or claim delivery.

The card exposes acknowledgement, explanation, and appeal-request affordances inherited from the
existing notification contract. Every card and route receipt remains simulated, non-disciplinary, and
unable to transition the Case. The default one-click startup does not invoke this post-confirmation
command.

## Consequences

The student notification center can show a confirmed PPE finding without leaking it to unrelated
students or leaders. Delivery and reply remain separate auditable slices and the default path remains
fully offline.
