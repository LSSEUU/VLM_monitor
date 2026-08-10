"""M8 offline notification card and workflow manifest authorities."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
)
from labcourt.contracts.references import ReferenceToken


class M8NotificationCardAction(StrEnum):
    ACKNOWLEDGE = "ACKNOWLEDGE"
    REQUEST_APPEAL = "REQUEST_APPEAL"
    SUBMIT_EXPLANATION = "SUBMIT_EXPLANATION"


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
            raise ValueError(
                f"serialized {name} conflicts with derived M8 notification card authority"
            )


class M8NotificationWorkflowManifestAuthorityV1(FrozenContractModel):
    """Pinned manifests for one notification application workflow deployment."""

    schema_version: Literal["m8-notification-workflow-manifest-authority-v1"] = (
        "m8-notification-workflow-manifest-authority-v1"
    )
    card_renderer_manifest_id: Sha256Hex
    dispatch_request_manifest_id: Sha256Hex
    transition_command_manifest_id: Sha256Hex
    raw_storage_manifest_id: Sha256Hex
    audit_manifest_id: Sha256Hex
    workflow_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(value, ("workflow_authority_id",))
        authority = handler(payload)
        _verify_computed_claims(authority, claims)
        return authority

    @computed_field  # type: ignore[prop-decorator]
    @property
    def workflow_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-notification-workflow-manifest-authority",
                1,
                self.card_renderer_manifest_id,
                self.dispatch_request_manifest_id,
                self.transition_command_manifest_id,
                self.raw_storage_manifest_id,
                self.audit_manifest_id,
                self.workflow_manifest_id,
            ]
        )


class M8OfflineNotificationCardV1(FrozenContractModel):
    """Canonical local card that preserves Case, template, and simulation authority."""

    schema_version: Literal["m8-offline-notification-card-v1"] = "m8-offline-notification-card-v1"
    plan: M8NotificationPlanAuthorityV1
    card_renderer_manifest_id: Sha256Hex

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
                "available_actions",
                "simulated",
                "display_badge",
                "direct_disciplinary_action_permitted",
                "case_transition_permitted",
                "external_delivery_claim_permitted",
                "real_delivery_confirmed",
                "card_id",
                "raw_card_ref",
            ),
        )
        card = handler(payload)
        _verify_computed_claims(card, claims)
        return card

    @model_validator(mode="after")
    def validate_offline_plan(self) -> Self:
        if self.plan.target.channel != M8NotificationChannelKind.LOCAL_OFFLINE_FAKE:
            raise ValueError("M8 offline notification card requires LOCAL_OFFLINE_FAKE plan")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def available_actions(self) -> tuple[M8NotificationCardAction, ...]:
        if not self.plan.target.inbound_response_supported:
            return ()
        return (
            M8NotificationCardAction.ACKNOWLEDGE,
            M8NotificationCardAction.REQUEST_APPEAL,
            M8NotificationCardAction.SUBMIT_EXPLANATION,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulated(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        return "SIMULATED · LOCAL MESSAGE CARD"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_transition_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_delivery_claim_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_delivery_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def card_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-offline-notification-card",
                1,
                self.plan.notification_id,
                self.plan.case_id,
                self.plan.case_version,
                self.plan.case_authority_sha256,
                self.plan.target.target_authority_id,
                self.plan.template.template_authority_id,
                [action.value for action in self.available_actions],
                self.card_renderer_manifest_id,
                self.simulated,
                self.direct_disciplinary_action_permitted,
                self.case_transition_permitted,
                self.external_delivery_claim_permitted,
                self.real_delivery_confirmed,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_card_ref(self) -> ReferenceToken:
        return f"m8-card-{self.card_id[:48]}"


__all__ = [
    "M8NotificationCardAction",
    "M8NotificationWorkflowManifestAuthorityV1",
    "M8OfflineNotificationCardV1",
]
