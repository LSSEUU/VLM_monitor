"""End-to-end authority for one claimed Feishu sandbox outbox attempt."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_transport import M8FeishuSandboxSendReceiptV1
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchCallFenceReceiptV1,
    M8NotificationDispatchClaimReceiptV1,
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.m8_notifications import M8NotificationChannelKind, M8NotificationStatus


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
            raise ValueError(f"serialized {name} conflicts with derived M8 Feishu outbox authority")


class M8FeishuSandboxOutboxRunReceiptV1(FrozenContractModel):
    """Exact preflight/claim/send/completion chain; never a delivery or Case claim."""

    schema_version: Literal["m8-feishu-sandbox-outbox-run-receipt-v1"] = (
        "m8-feishu-sandbox-outbox-run-receipt-v1"
    )
    claim: M8NotificationDispatchClaimReceiptV1
    call_fence: M8NotificationDispatchCallFenceReceiptV1
    send_receipt: M8FeishuSandboxSendReceiptV1
    completion: M8NotificationDispatchCompletionReceiptV1
    runner_manifest_id: Sha256Hex

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
                "notification_id",
                "attempt_number",
                "provider_message_request_attempted",
                "provider_acceptance_confirmed",
                "notification_transition_committed",
                "notification_status",
                "unknown_delivery",
                "real_delivery_confirmed",
                "credential_material_persisted",
                "automatic_retry_permitted",
                "case_transition_permitted",
                "direct_disciplinary_action_permitted",
                "run_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        preflight = self.send_receipt.preflight
        if self.claim.request != preflight.notification_request:
            raise ValueError("M8 Feishu outbox claim belongs to another preflight")
        if self.call_fence.claim != self.claim:
            raise ValueError("M8 Feishu outbox call fence belongs to another claim")
        if (
            self.call_fence.dispatch_authorization_id
            != self.send_receipt.activation_status.activation_receipt.activation_commit_id
        ):
            raise ValueError("M8 Feishu outbox call fence lacks the exact activation commit")
        if (
            self.completion.claim != self.claim
            or self.completion.call_fence != self.call_fence
            or self.completion.dispatch_result != self.send_receipt.dispatch_result
        ):
            raise ValueError("M8 Feishu outbox completion grafts another send attempt")
        if preflight.notification_request.plan.target.channel != M8NotificationChannelKind.FEISHU:
            raise ValueError("M8 Feishu outbox receipt requires a FEISHU notification")
        if self.completion.repository_manifest_id != self.claim.repository_manifest_id:
            raise ValueError("M8 Feishu outbox receipt crosses repositories")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_id(self) -> Sha256Hex:
        return self.claim.notification_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempt_number(self) -> int:
        return self.claim.attempt_number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_message_request_attempted(self) -> bool:
        return self.send_receipt.message_request_attempted

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_acceptance_confirmed(self) -> bool:
        return self.send_receipt.provider_acceptance_confirmed

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_transition_committed(self) -> bool:
        return self.completion.notification_transition_committed

    @computed_field  # type: ignore[prop-decorator]
    @property
    def notification_status(self) -> M8NotificationStatus:
        return self.completion.notification_commit.status

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unknown_delivery(self) -> bool:
        return (
            self.send_receipt.dispatch_result.disposition
            == M8NotificationDispatchDisposition.UNKNOWN_DELIVERY
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def real_delivery_confirmed(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def credential_material_persisted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def automatic_retry_permitted(self) -> bool:
        return False

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
    def run_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-feishu-sandbox-outbox-run-receipt",
                1,
                self.claim.claim_id,
                self.call_fence.call_fence_id,
                self.send_receipt.send_receipt_id,
                self.completion.completion_id,
                self.runner_manifest_id,
                self.notification_id,
                self.attempt_number,
                self.provider_message_request_attempted,
                self.provider_acceptance_confirmed,
                self.notification_transition_committed,
                self.notification_status,
                self.unknown_delivery,
                self.real_delivery_confirmed,
                self.credential_material_persisted,
                self.automatic_retry_permitted,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
            ]
        )


__all__ = ["M8FeishuSandboxOutboxRunReceiptV1"]
