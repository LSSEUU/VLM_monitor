"""Optimistically stable, read-only orchestration of the M8 operations projection."""

from __future__ import annotations

from pydantic import ValidationError

from labcourt.application.m8_projection_workflow import build_operations_projection
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_case_persistence import M8OperationalCaseCommitReceiptV1
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.m8_operations import MAX_M8_OPERATIONAL_SOURCES
from labcourt.contracts.m8_projections import (
    MAX_M8_PROJECTION_CASES,
    MAX_M8_PROJECTION_NOTIFICATIONS,
    M8OperationsProjectionV1,
)
from labcourt.contracts.m8_sensor_persistence import M8SensorSampleCommitReceiptV1
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m8_inventory_repository import M8InventoryRepository
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.ports.m8_sensor_persistence_repository import M8SensorPersistenceRepository

_MAX_STABLE_READ_ATTEMPTS = 3


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


class M8OperationsProjectionService:
    """Build a complete projection only when all optimistic read fences remain stable."""

    def __init__(
        self,
        inventory_repository: M8InventoryRepository,
        operations_repository: M8OperationsRepository,
        sensor_repository: M8SensorPersistenceRepository,
        notification_repository: M8NotificationRepository,
        projection_manifest_id: Sha256Hex,
    ) -> None:
        self._inventory = inventory_repository
        self._operations = operations_repository
        self._sensors = sensor_repository
        self._notifications = notification_repository
        self._projection_manifest_id = _validate_sha256(
            projection_manifest_id,
            "operations projection manifest",
        )

    def current_projection(self, campus_id: str) -> M8OperationsProjectionV1:
        for _attempt in range(_MAX_STABLE_READ_ATTEMPTS):
            topology = self._inventory.get_current_topology(campus_id)
            catalog = self._inventory.get_current_source_catalog(campus_id)
            cases = self._operations.list_current_operational_cases(MAX_M8_PROJECTION_CASES)
            samples = self._sensors.list_latest_sensor_samples(MAX_M8_OPERATIONAL_SOURCES)
            notifications = self._notifications.list_current_notifications(
                MAX_M8_PROJECTION_NOTIFICATIONS
            )
            campus_cases = self._campus_cases(topology, cases)
            campus_case_ids = {item.case_id for item in campus_cases}
            campus_notifications = tuple(
                item
                for item in notifications
                if item.audit_event.notification_authority.plan.case_id in campus_case_ids
            )
            case_audit = tuple(
                event
                for receipt in campus_cases
                for event in self._operations.list_operational_case_audit(receipt.case_id)
            )
            notification_audit = tuple(
                event
                for receipt in campus_notifications
                for event in self._notifications.list_notification_audit(receipt.notification_id)
            )
            if not self._fences_stable(
                campus_id,
                topology,
                catalog,
                cases,
                samples,
                notifications,
            ):
                continue
            try:
                return build_operations_projection(
                    topology,
                    catalog,
                    samples,
                    campus_cases,
                    case_audit,
                    campus_notifications,
                    notification_audit,
                    self._projection_manifest_id,
                )
            except ValidationError as error:
                raise ConcurrentModification(
                    "M8 operations projection cut does not close over current authorities"
                ) from error
        raise ConcurrentModification("M8 operations projection changed during bounded read")

    @staticmethod
    def _campus_cases(
        topology: M8CampusTopologyCommitReceiptV1,
        cases: tuple[M8OperationalCaseCommitReceiptV1, ...],
    ) -> tuple[M8OperationalCaseCommitReceiptV1, ...]:
        location_ids = {item.location_id for item in topology.topology.locations}
        return tuple(
            item for item in cases if item.audit_event.case_authority.location_id in location_ids
        )

    def _fences_stable(
        self,
        campus_id: str,
        topology: M8CampusTopologyCommitReceiptV1,
        catalog: M8OperationalSourceCatalogCommitReceiptV1,
        cases: tuple[M8OperationalCaseCommitReceiptV1, ...],
        samples: tuple[M8SensorSampleCommitReceiptV1, ...],
        notifications: tuple[M8NotificationCommitReceiptV1, ...],
    ) -> bool:
        return (
            self._inventory.get_current_topology(campus_id).commit_receipt_id
            == topology.commit_receipt_id
            and self._inventory.get_current_source_catalog(campus_id).commit_receipt_id
            == catalog.commit_receipt_id
            and self._case_fence() == tuple(item.commit_receipt_id for item in cases)
            and self._sample_fence() == tuple(item.commit_receipt_id for item in samples)
            and self._notification_fence()
            == tuple(item.commit_receipt_id for item in notifications)
        )

    def _case_fence(self) -> tuple[str, ...]:
        return tuple(
            item.commit_receipt_id
            for item in self._operations.list_current_operational_cases(MAX_M8_PROJECTION_CASES)
        )

    def _sample_fence(self) -> tuple[str, ...]:
        return tuple(
            item.commit_receipt_id
            for item in self._sensors.list_latest_sensor_samples(MAX_M8_OPERATIONAL_SOURCES)
        )

    def _notification_fence(self) -> tuple[str, ...]:
        return tuple(
            item.commit_receipt_id
            for item in self._notifications.list_current_notifications(
                MAX_M8_PROJECTION_NOTIFICATIONS
            )
        )


__all__ = ["M8OperationsProjectionService"]
