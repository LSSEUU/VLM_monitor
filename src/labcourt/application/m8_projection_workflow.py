"""Pure construction of a read-only M8 campus operations projection."""

from __future__ import annotations

from labcourt.contracts.frames import Sha256Hex
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
from labcourt.contracts.m8_projections import (
    M8OperationsProjectionV1,
    M8ProjectionSourceV1,
)
from labcourt.contracts.m8_sensor_persistence import M8SensorSampleCommitReceiptV1


def build_operations_projection(
    topology_receipt: M8CampusTopologyCommitReceiptV1,
    source_catalog_receipt: M8OperationalSourceCatalogCommitReceiptV1,
    latest_sensor_samples: tuple[M8SensorSampleCommitReceiptV1, ...],
    current_cases: tuple[M8OperationalCaseCommitReceiptV1, ...],
    case_audit_events: tuple[M8OperationalCaseAuditEventV1, ...],
    current_notifications: tuple[M8NotificationCommitReceiptV1, ...],
    notification_audit_events: tuple[M8NotificationAuditEventV1, ...],
    projection_manifest_id: Sha256Hex,
) -> M8OperationsProjectionV1:
    sample_source_ids = tuple(item.sample.source_id for item in latest_sensor_samples)
    if sample_source_ids != tuple(sorted(sample_source_ids)) or len(sample_source_ids) != len(
        set(sample_source_ids)
    ):
        raise ValueError("M8 latest projection samples must be unique and stably ordered")
    catalog_receipt_id = source_catalog_receipt.commit_receipt_id
    catalog_id = source_catalog_receipt.catalog.catalog_id
    samples_by_source = {
        item.sample.source_id: item
        for item in latest_sensor_samples
        if item.sample.source_catalog_id == catalog_id
        and item.resolved_source_catalog_commit_receipt_id == catalog_receipt_id
    }
    return M8OperationsProjectionV1(
        topology_receipt=topology_receipt,
        source_catalog_receipt=source_catalog_receipt,
        sources=tuple(
            M8ProjectionSourceV1(
                source=source,
                latest_sample_receipt=samples_by_source.get(source.source_id),
            )
            for source in source_catalog_receipt.catalog.sources
        ),
        current_cases=current_cases,
        case_audit_events=case_audit_events,
        current_notifications=current_notifications,
        notification_audit_events=notification_audit_events,
        projection_manifest_id=projection_manifest_id,
    )


__all__ = ["build_operations_projection"]
