# ADR 0092: Device health and sensor discovery reuse the projection

## Decision

The personal Demo exposes campus-scoped `device-health` and `sensors` GET
resources by reusing existing typed `M8ProjectionSourceV1` values from the
current role-scoped operations projection. Sensor discovery is a strict filter
over source kind; device health returns every catalog source with its latest
persisted sensor sample and derived observation state.

No parallel device inventory, freshness guess, or untyped health string is
introduced.

## Consequences

- Leader, safety and operations views share one current catalog/sample cut.
- Students remain forbidden from operational device inventory.
- Simulation and non-certified life-safety limits remain visible in every item.
