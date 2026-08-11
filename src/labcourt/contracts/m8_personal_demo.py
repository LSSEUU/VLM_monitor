"""Compact authorities for the reproducible local M8 product demonstration."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, computed_field, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import (
    M8ActorRole,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.references import ReferenceToken, require_reference_token


class M8PersonalDemoActorBindingV1(FrozenContractModel):
    schema_version: Literal["m8-personal-demo-actor-binding-v1"] = (
        "m8-personal-demo-actor-binding-v1"
    )
    actor_id: ReferenceToken
    role: M8ActorRole
    actor_commit_receipt_id: Sha256Hex

    @model_validator(mode="after")
    def validate_actor_id(self) -> Self:
        require_reference_token(self.actor_id, "M8 personal demo actor_id")
        return self


class M8PersonalDemoBootstrapReceiptV1(FrozenContractModel):
    """Small content-addressed receipt over the complete persisted demo cut."""

    schema_version: Literal["m8-personal-demo-bootstrap-receipt-v1"] = (
        "m8-personal-demo-bootstrap-receipt-v1"
    )
    display_badge: Literal["PERSONAL DEMO · SIMULATED CAMPUS OPERATIONS"] = (
        "PERSONAL DEMO · SIMULATED CAMPUS OPERATIONS"
    )
    campus_id: Literal["campus-demo"] = "campus-demo"
    case_location_id: Literal["room-chem-301"] = "room-chem-301"
    source_id: Literal["sensor-simulated-smoke-01"] = "sensor-simulated-smoke-01"
    topology_commit_receipt_id: Sha256Hex
    source_catalog_commit_receipt_id: Sha256Hex
    actor_bindings: tuple[M8PersonalDemoActorBindingV1, ...] = Field(
        min_length=4,
        max_length=4,
    )
    sensor_poll_cache_commit_receipt_id: Sha256Hex
    latest_sensor_sample_commit_receipt_id: Sha256Hex
    raw_signal_refs: tuple[str, ...] = Field(min_length=2, max_length=2)
    case_commit_receipt_id: Sha256Hex
    case_id: Sha256Hex
    case_status: Literal[M8OperationalCaseStatus.PENDING_VERIFICATION] = (
        M8OperationalCaseStatus.PENDING_VERIFICATION
    )
    risk_level: Literal[M8OperationalRiskLevel.EMERGENCY] = M8OperationalRiskLevel.EMERGENCY
    operations_projection_id: Sha256Hex
    location_count: Literal[4] = 4
    source_count: Literal[1] = 1
    observed_sensor_count: Literal[1] = 1
    current_case_count: Literal[1] = 1
    pending_verification_case_count: Literal[1] = 1
    simulated: Literal[True] = True
    certified_fire_detection_claim_permitted: Literal[False] = False
    human_verification_required: Literal[True] = True
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False
    bootstrap_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_computed_claim(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        claimed: object | None = None
        present = False
        if isinstance(value, dict):
            payload = dict(value)
            present = "bootstrap_receipt_id" in payload
            claimed = payload.pop("bootstrap_receipt_id", None)
            value = payload
        receipt = handler(value)
        if present and canonical_json(claimed) != canonical_json(receipt.bootstrap_receipt_id):
            raise ValueError("serialized bootstrap receipt ID conflicts with derived authority")
        return receipt

    @model_validator(mode="after")
    def validate_fixed_inventory(self) -> Self:
        expected = (
            ("leader-demo", M8ActorRole.LEADER),
            ("operations-demo", M8ActorRole.OPERATIONS),
            ("safety-officer-demo", M8ActorRole.SAFETY_OFFICER),
            ("student-demo", M8ActorRole.STUDENT),
        )
        observed = tuple((item.actor_id, item.role) for item in self.actor_bindings)
        if observed != expected:
            raise ValueError("M8 personal demo actor inventory is not the fixed role matrix")
        commit_ids = tuple(item.actor_commit_receipt_id for item in self.actor_bindings)
        if len(commit_ids) != len(set(commit_ids)):
            raise ValueError("M8 personal demo actor commits must be unique")
        if self.raw_signal_refs != tuple(sorted(self.raw_signal_refs)):
            raise ValueError("M8 personal demo raw signal refs must use stable order")
        if len(set(self.raw_signal_refs)) != 2:
            raise ValueError("M8 personal demo raw signal refs must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def bootstrap_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-personal-demo-bootstrap-receipt",
                1,
                self.campus_id,
                self.case_location_id,
                self.source_id,
                self.topology_commit_receipt_id,
                self.source_catalog_commit_receipt_id,
                [item.model_dump(mode="json") for item in self.actor_bindings],
                self.sensor_poll_cache_commit_receipt_id,
                self.latest_sensor_sample_commit_receipt_id,
                self.raw_signal_refs,
                self.case_commit_receipt_id,
                self.case_id,
                self.case_status,
                self.risk_level,
                self.operations_projection_id,
                self.location_count,
                self.source_count,
                self.observed_sensor_count,
                self.current_case_count,
                self.pending_verification_case_count,
                self.simulated,
                self.certified_fire_detection_claim_permitted,
                self.human_verification_required,
                self.case_transition_permitted,
                self.direct_disciplinary_action_permitted,
                self.bootstrap_manifest_id,
            ]
        )


__all__ = [
    "M8PersonalDemoActorBindingV1",
    "M8PersonalDemoBootstrapReceiptV1",
]
