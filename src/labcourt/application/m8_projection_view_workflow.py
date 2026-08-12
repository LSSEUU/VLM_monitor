"""Pure role filtering for one complete M8 operations projection."""

from __future__ import annotations

from labcourt.application.m8_projection_workflow import build_operations_projection
from labcourt.contracts.m8_access_cases import M8ActorRole, M8OperationalRiskLevel
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_projection_views import M8OperationsProjectionViewV1
from labcourt.contracts.m8_projections import M8OperationsProjectionV1

_MAJOR_RISKS = frozenset({M8OperationalRiskLevel.SEVERE, M8OperationalRiskLevel.EMERGENCY})


def build_operations_projection_view(
    projection: M8OperationsProjectionV1,
    viewer_actor_receipt: M8ActorAuthorityCommitReceiptV1,
) -> M8OperationsProjectionViewV1:
    actor = viewer_actor_receipt.authority
    if not actor.active or actor.role == M8ActorRole.STUDENT:
        raise ValueError("M8 actor cannot view the operations projection")
    if actor.role == M8ActorRole.SAFETY_OFFICER:
        visible = projection
    else:
        if actor.role == M8ActorRole.LEADER:
            cases = tuple(
                item
                for item in projection.current_cases
                if item.audit_event.case_authority.risk_level in _MAJOR_RISKS
            )
            case_ids = {item.case_id for item in cases}
            notifications = tuple(
                item
                for item in projection.current_notifications
                if item.audit_event.notification_authority.plan.case_id in case_ids
            )
            notification_ids = {item.notification_id for item in notifications}
        elif actor.role == M8ActorRole.OPERATIONS:
            cases = ()
            case_ids = set()
            notifications = ()
            notification_ids = set()
        else:  # pragma: no cover - closed role enum and student handled above
            raise ValueError("unsupported M8 projection viewer role")
        visible = build_operations_projection(
            projection.topology_receipt,
            projection.source_catalog_receipt,
            tuple(
                item.latest_sample_receipt
                for item in projection.sources
                if item.latest_sample_receipt is not None
            ),
            cases,
            tuple(
                item
                for item in projection.case_audit_events
                if item.case_authority.case_id in case_ids
            ),
            notifications,
            tuple(
                item
                for item in projection.notification_audit_events
                if item.notification_authority.notification_id in notification_ids
            ),
            projection.projection_manifest_id,
        )
    return M8OperationsProjectionViewV1(
        viewer_actor_receipt=viewer_actor_receipt,
        source_projection_id=projection.projection_id,
        visible_projection=visible,
    )


__all__ = ["build_operations_projection_view"]
