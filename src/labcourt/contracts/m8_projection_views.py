"""Role-scoped, read-only views over one complete M8 operations projection."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8Capability,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_projections import M8OperationsProjectionV1

_MAJOR_RISKS = frozenset({M8OperationalRiskLevel.SEVERE, M8OperationalRiskLevel.EMERGENCY})


class M8ProjectionViewKind(StrEnum):
    LEADER_GLOBAL_MAJOR = "LEADER_GLOBAL_MAJOR"
    OPERATIONS_DEVICES = "OPERATIONS_DEVICES"
    SAFETY_FULL = "SAFETY_FULL"


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
    if not any(present for present, _claimed in claims.values()):
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 projection view")


class M8OperationsProjectionViewV1(FrozenContractModel):
    """A role-scoped projection that never grants mutation capability."""

    schema_version: Literal["m8-operations-projection-view-v1"] = "m8-operations-projection-view-v1"
    viewer_actor_receipt: M8ActorAuthorityCommitReceiptV1
    source_projection_id: Sha256Hex
    visible_projection: M8OperationsProjectionV1

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
                "view_kind",
                "projection_write_permitted",
                "case_action_permitted",
                "direct_disciplinary_action_permitted",
                "view_id",
            ),
        )
        view = handler(payload)
        _verify_computed_claims(view, claims)
        return view

    @model_validator(mode="after")
    def validate_role_scope(self) -> Self:
        actor = self.viewer_actor_receipt.authority
        if not actor.active:
            raise ValueError("M8 projection viewer must be active")
        if actor.role == M8ActorRole.STUDENT:
            raise ValueError("M8 students cannot access the operations projection")
        required_capability = {
            M8ActorRole.LEADER: M8Capability.VIEW_GLOBAL_OVERVIEW,
            M8ActorRole.SAFETY_OFFICER: M8Capability.VIEW_GLOBAL_OVERVIEW,
            M8ActorRole.OPERATIONS: M8Capability.VIEW_DEVICE_HEALTH,
        }[actor.role]
        if required_capability not in actor.capabilities:
            raise ValueError("M8 projection viewer lacks the required persisted capability")
        projection = self.visible_projection
        if actor.role == M8ActorRole.LEADER and any(
            item.audit_event.case_authority.risk_level not in _MAJOR_RISKS
            for item in projection.current_cases
        ):
            raise ValueError("M8 leader projection can contain only major Cases")
        if actor.role == M8ActorRole.OPERATIONS and (
            projection.current_cases
            or projection.case_audit_events
            or projection.current_notifications
            or projection.notification_audit_events
        ):
            raise ValueError("M8 operations projection cannot expose Case or notification data")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def view_kind(self) -> M8ProjectionViewKind:
        role = self.viewer_actor_receipt.authority.role
        return {
            M8ActorRole.LEADER: M8ProjectionViewKind.LEADER_GLOBAL_MAJOR,
            M8ActorRole.SAFETY_OFFICER: M8ProjectionViewKind.SAFETY_FULL,
            M8ActorRole.OPERATIONS: M8ProjectionViewKind.OPERATIONS_DEVICES,
        }[role]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def projection_write_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def view_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operations-projection-view",
                1,
                self.viewer_actor_receipt.authority.actor_authority_id,
                self.viewer_actor_receipt.authority_document_sha256,
                self.source_projection_id,
                self.visible_projection.projection_id,
                self.view_kind,
                self.projection_write_permitted,
                self.case_action_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = ["M8OperationsProjectionViewV1", "M8ProjectionViewKind"]
