"""M8 read-only campus operations projection authorities."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import (
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationAuditEventV1,
    M8NotificationCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.contracts.m8_operations import (
    MAX_M8_CAMPUS_LOCATIONS,
    MAX_M8_OPERATIONAL_SOURCES,
    M8CampusLocation,
    M8OperationalSource,
    M8OperationalSourceKind,
    M8OperationalSourceMode,
)
from labcourt.contracts.m8_sensor_persistence import M8SensorSampleCommitReceiptV1

MAX_M8_PROJECTION_CASES = 10_000
MAX_M8_PROJECTION_NOTIFICATIONS = 20_000
MAX_M8_PROJECTION_AUDIT_EVENTS = 50_000

_ACTIVE_CASE_STATUSES = frozenset(
    {
        M8OperationalCaseStatus.PENDING_VERIFICATION,
        M8OperationalCaseStatus.CONFIRMED,
        M8OperationalCaseStatus.EVIDENCE_REQUESTED,
        M8OperationalCaseStatus.APPEALED,
    }
)
_MAJOR_RISK_LEVELS = frozenset({M8OperationalRiskLevel.SEVERE, M8OperationalRiskLevel.EMERGENCY})
_TERMINAL_NOTIFICATION_STATUSES = frozenset(
    {M8NotificationStatus.ACKNOWLEDGED, M8NotificationStatus.RESPONDED}
)


class M8ProjectionSourceObservationState(StrEnum):
    SOURCE_CATALOG_ONLY = "SOURCE_CATALOG_ONLY"
    NO_PERSISTED_SAMPLE = "NO_PERSISTED_SAMPLE"
    PERSISTED_LIVE_SENSOR_SAMPLE = "PERSISTED_LIVE_SENSOR_SAMPLE"
    PERSISTED_SIMULATED_SENSOR_SAMPLE = "PERSISTED_SIMULATED_SENSOR_SAMPLE"


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 projection")


class M8ProjectionSourceV1(FrozenContractModel):
    """One catalog source plus its latest persisted sensor sample, if any."""

    schema_version: Literal["m8-projection-source-v1"] = "m8-projection-source-v1"
    source: M8OperationalSource
    latest_sample_receipt: M8SensorSampleCommitReceiptV1 | None = None

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "observation_state",
                "display_badge",
                "simulated",
                "live_observation_confirmed",
                "certified_fire_detection_claim_permitted",
                "source_projection_id",
            ),
        )
        projection = handler(payload)
        _verify_computed_claims(projection, claims)
        return projection

    @model_validator(mode="after")
    def validate_sample_binding(self) -> Self:
        if self.source.source_kind == M8OperationalSourceKind.CAMERA:
            if self.latest_sample_receipt is not None:
                raise ValueError("M8 camera projection cannot graft a sensor sample")
            return self
        if (
            self.latest_sample_receipt is not None
            and self.latest_sample_receipt.sample.source != self.source
        ):
            raise ValueError("M8 projection sample does not bind its source authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def observation_state(self) -> M8ProjectionSourceObservationState:
        if self.source.source_kind == M8OperationalSourceKind.CAMERA:
            return M8ProjectionSourceObservationState.SOURCE_CATALOG_ONLY
        if self.latest_sample_receipt is None:
            return M8ProjectionSourceObservationState.NO_PERSISTED_SAMPLE
        if self.source.mode == M8OperationalSourceMode.SIMULATED_SENSOR:
            return M8ProjectionSourceObservationState.PERSISTED_SIMULATED_SENSOR_SAMPLE
        return M8ProjectionSourceObservationState.PERSISTED_LIVE_SENSOR_SAMPLE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        return self.source.display_badge

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return self.source.simulated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def live_observation_confirmed(self) -> bool:
        return (
            self.observation_state
            == M8ProjectionSourceObservationState.PERSISTED_LIVE_SENSOR_SAMPLE
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def certified_fire_detection_claim_permitted(self) -> bool:
        return bool(
            self.live_observation_confirmed
            and self.source.life_safety_eligible
            and self.latest_sample_receipt is not None
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_projection_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-projection-source",
                1,
                self.source.source_id,
                self.source.manifest_id,
                (
                    self.latest_sample_receipt.commit_receipt_id
                    if self.latest_sample_receipt is not None
                    else None
                ),
                self.observation_state,
                self.display_badge,
                self.simulated,
                self.live_observation_confirmed,
                self.certified_fire_detection_claim_permitted,
            ]
        )


class M8ProjectionOverviewV1(FrozenContractModel):
    schema_version: Literal["m8-projection-overview-v1"] = "m8-projection-overview-v1"
    location_count: int = Field(ge=0, strict=True)
    source_count: int = Field(ge=0, strict=True)
    camera_count: int = Field(ge=0, strict=True)
    sensor_count: int = Field(ge=0, strict=True)
    simulated_source_count: int = Field(ge=0, strict=True)
    observed_sensor_count: int = Field(ge=0, strict=True)
    current_case_count: int = Field(ge=0, strict=True)
    pending_verification_case_count: int = Field(ge=0, strict=True)
    active_major_case_count: int = Field(ge=0, strict=True)
    current_notification_count: int = Field(ge=0, strict=True)
    unresolved_notification_count: int = Field(ge=0, strict=True)
    case_audit_event_count: int = Field(ge=0, strict=True)
    notification_audit_event_count: int = Field(ge=0, strict=True)


class M8ProjectionMapNodeV1(FrozenContractModel):
    schema_version: Literal["m8-projection-map-node-v1"] = "m8-projection-map-node-v1"
    location: M8CampusLocation
    child_location_ids: tuple[str, ...] = Field(max_length=MAX_M8_CAMPUS_LOCATIONS)
    source_ids: tuple[str, ...] = Field(max_length=MAX_M8_OPERATIONAL_SOURCES)
    simulated_source_ids: tuple[str, ...] = Field(max_length=MAX_M8_OPERATIONAL_SOURCES)
    current_case_ids: tuple[Sha256Hex, ...] = Field(max_length=MAX_M8_PROJECTION_CASES)
    active_major_case_ids: tuple[Sha256Hex, ...] = Field(max_length=MAX_M8_PROJECTION_CASES)

    @model_validator(mode="after")
    def validate_stable_subsets(self) -> Self:
        inventories = (
            self.child_location_ids,
            self.source_ids,
            self.simulated_source_ids,
            self.current_case_ids,
            self.active_major_case_ids,
        )
        if any(inventory != tuple(sorted(inventory)) for inventory in inventories):
            raise ValueError("M8 projection map inventories must use stable order")
        if not set(self.simulated_source_ids).issubset(self.source_ids):
            raise ValueError("M8 simulated map sources must be a source subset")
        if not set(self.active_major_case_ids).issubset(self.current_case_ids):
            raise ValueError("M8 major map cases must be a current Case subset")
        return self


class M8OperationsProjectionV1(FrozenContractModel):
    """One complete read-only cut over current M8 campus operations authorities."""

    schema_version: Literal["m8-operations-projection-v1"] = "m8-operations-projection-v1"
    topology_receipt: M8CampusTopologyCommitReceiptV1
    source_catalog_receipt: M8OperationalSourceCatalogCommitReceiptV1
    sources: tuple[M8ProjectionSourceV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_OPERATIONAL_SOURCES,
    )
    current_cases: tuple[M8OperationalCaseCommitReceiptV1, ...] = Field(
        max_length=MAX_M8_PROJECTION_CASES
    )
    case_audit_events: tuple[M8OperationalCaseAuditEventV1, ...] = Field(
        max_length=MAX_M8_PROJECTION_AUDIT_EVENTS
    )
    current_notifications: tuple[M8NotificationCommitReceiptV1, ...] = Field(
        max_length=MAX_M8_PROJECTION_NOTIFICATIONS
    )
    notification_audit_events: tuple[M8NotificationAuditEventV1, ...] = Field(
        max_length=MAX_M8_PROJECTION_AUDIT_EVENTS
    )
    projection_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "overview",
                "map_nodes",
                "source_projection_inventory_sha256",
                "case_inventory_sha256",
                "notification_inventory_sha256",
                "case_audit_inventory_sha256",
                "notification_audit_inventory_sha256",
                "read_only",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "projection_id",
            ),
        )
        projection = handler(payload)
        _verify_computed_claims(projection, claims)
        return projection

    @model_validator(mode="after")
    def validate_closed_cut(self) -> Self:
        topology = self.topology_receipt.topology
        catalog_receipt = self.source_catalog_receipt
        catalog = catalog_receipt.catalog
        if (
            catalog.topology != topology
            or catalog_receipt.resolved_topology_commit_receipt_id
            != self.topology_receipt.commit_receipt_id
        ):
            raise ValueError("M8 projection source catalog does not bind its topology receipt")
        if tuple(item.source for item in self.sources) != catalog.sources:
            raise ValueError("M8 projection sources do not exactly close the catalog inventory")
        for item in self.sources:
            sample_receipt = item.latest_sample_receipt
            if sample_receipt is not None and (
                sample_receipt.sample.source_catalog_id != catalog.catalog_id
                or sample_receipt.resolved_source_catalog_commit_receipt_id
                != catalog_receipt.commit_receipt_id
            ):
                raise ValueError("M8 projection sample uses another source catalog receipt")

        case_ids = tuple(item.case_id for item in self.current_cases)
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("M8 projection current cases must be unique and stably ordered")
        known_locations = {item.location_id for item in topology.locations}
        known_sources = {item.source_id for item in catalog.sources}
        for receipt in self.current_cases:
            authority = receipt.audit_event.case_authority
            if authority.location_id not in known_locations or not set(
                authority.source_ids
            ).issubset(known_sources):
                raise ValueError("M8 projection Case is outside the topology or source catalog")
        self._validate_case_audit_closure()

        notification_ids = tuple(item.notification_id for item in self.current_notifications)
        if notification_ids != tuple(sorted(notification_ids)) or len(notification_ids) != len(
            set(notification_ids)
        ):
            raise ValueError("M8 projection notifications must be unique and stably ordered")
        known_case_ids = set(case_ids)
        if any(
            item.audit_event.notification_authority.plan.case_id not in known_case_ids
            for item in self.current_notifications
        ):
            raise ValueError("M8 projection notification references an absent Case")
        self._validate_notification_audit_closure()
        return self

    def _validate_case_audit_closure(self) -> None:
        keys = tuple(
            (item.case_authority.case_id, item.event_sequence) for item in self.case_audit_events
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 projection Case audit must be unique and stably ordered")
        by_case_id: dict[str, list[M8OperationalCaseAuditEventV1]] = {}
        for event in self.case_audit_events:
            by_case_id.setdefault(event.case_authority.case_id, []).append(event)
        for receipt in self.current_cases:
            events = tuple(by_case_id.get(receipt.case_id, ()))
            if (
                tuple(item.event_sequence for item in events)
                != tuple(range(1, receipt.case_version + 1))
                or not events
                or events[-1] != receipt.audit_event
            ):
                raise ValueError("M8 projection Case audit does not close the current receipt")
        if not set(by_case_id).issubset(receipt.case_id for receipt in self.current_cases):
            raise ValueError("M8 projection Case audit references an absent current Case")

    def _validate_notification_audit_closure(self) -> None:
        keys = tuple(
            (item.notification_authority.notification_id, item.event_sequence)
            for item in self.notification_audit_events
        )
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("M8 projection notification audit must be unique and stable")
        by_notification_id: dict[str, list[M8NotificationAuditEventV1]] = {}
        for event in self.notification_audit_events:
            by_notification_id.setdefault(
                event.notification_authority.notification_id,
                [],
            ).append(event)
        for receipt in self.current_notifications:
            events = tuple(by_notification_id.get(receipt.notification_id, ()))
            if (
                tuple(item.event_sequence for item in events)
                != tuple(range(1, receipt.notification_version + 1))
                or not events
                or events[-1] != receipt.audit_event
            ):
                raise ValueError(
                    "M8 projection notification audit does not close the current receipt"
                )
        current_ids = {receipt.notification_id for receipt in self.current_notifications}
        if not set(by_notification_id).issubset(current_ids):
            raise ValueError("M8 projection notification audit references an absent notification")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def overview(self) -> M8ProjectionOverviewV1:
        return M8ProjectionOverviewV1(
            location_count=len(self.topology_receipt.topology.locations),
            source_count=len(self.sources),
            camera_count=sum(
                item.source.source_kind == M8OperationalSourceKind.CAMERA for item in self.sources
            ),
            sensor_count=sum(
                item.source.source_kind == M8OperationalSourceKind.SENSOR for item in self.sources
            ),
            simulated_source_count=sum(item.simulated for item in self.sources),
            observed_sensor_count=sum(
                item.latest_sample_receipt is not None for item in self.sources
            ),
            current_case_count=len(self.current_cases),
            pending_verification_case_count=sum(
                item.status == M8OperationalCaseStatus.PENDING_VERIFICATION
                for item in self.current_cases
            ),
            active_major_case_count=sum(
                item.status in _ACTIVE_CASE_STATUSES
                and item.audit_event.case_authority.risk_level in _MAJOR_RISK_LEVELS
                for item in self.current_cases
            ),
            current_notification_count=len(self.current_notifications),
            unresolved_notification_count=sum(
                item.status not in _TERMINAL_NOTIFICATION_STATUSES
                for item in self.current_notifications
            ),
            case_audit_event_count=len(self.case_audit_events),
            notification_audit_event_count=len(self.notification_audit_events),
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def map_nodes(self) -> tuple[M8ProjectionMapNodeV1, ...]:
        nodes: list[M8ProjectionMapNodeV1] = []
        topology = self.topology_receipt.topology
        parents = {item.location_id: item.parent_location_id for item in topology.locations}
        child_ids: dict[str, list[str]] = {item.location_id: [] for item in topology.locations}
        source_ids: dict[str, list[str]] = {item.location_id: [] for item in topology.locations}
        simulated_source_ids: dict[str, list[str]] = {
            item.location_id: [] for item in topology.locations
        }
        case_ids: dict[str, list[str]] = {item.location_id: [] for item in topology.locations}
        active_major_case_ids: dict[str, list[str]] = {
            item.location_id: [] for item in topology.locations
        }
        for location in topology.locations:
            if location.parent_location_id is not None:
                child_ids[location.parent_location_id].append(location.location_id)
        for source_projection in self.sources:
            location_id: str | None = source_projection.source.location_id
            while location_id is not None:
                source_ids[location_id].append(source_projection.source.source_id)
                if source_projection.simulated:
                    simulated_source_ids[location_id].append(source_projection.source.source_id)
                location_id = parents[location_id]
        for case_receipt in self.current_cases:
            location_id = case_receipt.audit_event.case_authority.location_id
            while location_id is not None:
                case_ids[location_id].append(case_receipt.case_id)
                if (
                    case_receipt.status in _ACTIVE_CASE_STATUSES
                    and case_receipt.audit_event.case_authority.risk_level in _MAJOR_RISK_LEVELS
                ):
                    active_major_case_ids[location_id].append(case_receipt.case_id)
                location_id = parents[location_id]
        for location in topology.locations:
            nodes.append(
                M8ProjectionMapNodeV1(
                    location=location,
                    child_location_ids=tuple(sorted(child_ids[location.location_id])),
                    source_ids=tuple(sorted(source_ids[location.location_id])),
                    simulated_source_ids=tuple(sorted(simulated_source_ids[location.location_id])),
                    current_case_ids=tuple(sorted(case_ids[location.location_id])),
                    active_major_case_ids=tuple(
                        sorted(active_major_case_ids[location.location_id])
                    ),
                )
            )
        return tuple(nodes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_projection_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.source_projection_id for item in self.sources])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.commit_receipt_id for item in self.current_cases])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.commit_receipt_id for item in self.current_notifications])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_audit_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.audit_event_id for item in self.case_audit_events])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_audit_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex([item.audit_event_id for item in self.notification_audit_events])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def read_only(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def projection_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operations-projection",
                1,
                self.topology_receipt.commit_receipt_id,
                self.source_catalog_receipt.commit_receipt_id,
                self.source_projection_inventory_sha256,
                self.case_inventory_sha256,
                self.notification_inventory_sha256,
                self.case_audit_inventory_sha256,
                self.notification_audit_inventory_sha256,
                self.projection_manifest_id,
                self.read_only,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = [
    "MAX_M8_PROJECTION_AUDIT_EVENTS",
    "MAX_M8_PROJECTION_CASES",
    "MAX_M8_PROJECTION_NOTIFICATIONS",
    "M8OperationsProjectionV1",
    "M8ProjectionMapNodeV1",
    "M8ProjectionOverviewV1",
    "M8ProjectionSourceObservationState",
    "M8ProjectionSourceV1",
]
