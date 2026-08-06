"""Static violation registry: classification is a type-level policy."""

from __future__ import annotations

from pydantic import Field, StrictBool, StrictFloat, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import (
    AnchorType,
    EvidenceClass,
    PpeType,
    RiskLevel,
    ViolationType,
)


class ViolationDefinition(FrozenContractModel):
    violation_type: ViolationType
    evidence_class: EvidenceClass
    is_hard_rule_eligible: StrictBool
    required_zone_risk: RiskLevel | None
    required_targets: tuple[str, ...] = ()
    required_ppe: tuple[PpeType, ...] = ()
    anchor_type: AnchorType | None = None
    default_dwell_seconds: StrictFloat = Field(ge=0)
    default_cooldown_seconds: StrictFloat = Field(ge=0)
    screening_prompt_id: str = Field(min_length=1)
    alert_policy_key: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evidence_class_fields(self) -> ViolationDefinition:
        if self.evidence_class == EvidenceClass.ABSENCE:
            if not self.required_ppe or self.anchor_type is None:
                raise ValueError("absence violations require PPE and anchor_type")
        elif self.required_ppe or self.anchor_type is not None:
            raise ValueError("presence violations cannot declare absence-only fields")
        return self


VIOLATION_REGISTRY: dict[ViolationType, ViolationDefinition] = {
    ViolationType.PPE_GOGGLES_MISSING: ViolationDefinition(
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=RiskLevel.HIGH,
        required_ppe=(PpeType.GOGGLES,),
        anchor_type=AnchorType.HEAD,
        default_dwell_seconds=5,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_absence_v1",
        alert_policy_key="ppe_missing",
    ),
    ViolationType.PPE_GLOVES_MISSING: ViolationDefinition(
        violation_type=ViolationType.PPE_GLOVES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=RiskLevel.HIGH,
        required_ppe=(PpeType.GLOVES,),
        anchor_type=AnchorType.HANDS,
        default_dwell_seconds=5,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_absence_v1",
        alert_policy_key="ppe_missing",
    ),
    ViolationType.PPE_LAB_COAT_MISSING: ViolationDefinition(
        violation_type=ViolationType.PPE_LAB_COAT_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=RiskLevel.MEDIUM,
        required_ppe=(PpeType.LAB_COAT,),
        anchor_type=AnchorType.TORSO,
        default_dwell_seconds=10,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_absence_v1",
        alert_policy_key="ppe_missing",
    ),
    ViolationType.REAGENT_CONTAINER_OPEN: ViolationDefinition(
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=None,
        required_targets=("reagent_bottle", "bottle_cap"),
        default_dwell_seconds=3,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="unsafe_condition",
    ),
    ViolationType.FOOD_OR_DRINK_IN_LAB: ViolationDefinition(
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=None,
        required_targets=("food",),
        default_dwell_seconds=3,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="unsafe_condition",
    ),
    ViolationType.SINGLE_PERSON_HAZARDOUS_OPERATION: ViolationDefinition(
        violation_type=ViolationType.SINGLE_PERSON_HAZARDOUS_OPERATION,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=RiskLevel.HIGH,
        required_targets=("person",),
        default_dwell_seconds=3,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="unsafe_operation",
    ),
    ViolationType.FUME_HOOD_SASH_TOO_HIGH: ViolationDefinition(
        violation_type=ViolationType.FUME_HOOD_SASH_TOO_HIGH,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=False,
        required_zone_risk=None,
        required_targets=("fume_sash",),
        default_dwell_seconds=3,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="unsafe_condition",
    ),
    ViolationType.UNATTENDED_HEATING: ViolationDefinition(
        violation_type=ViolationType.UNATTENDED_HEATING,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=True,
        required_zone_risk=RiskLevel.HIGH,
        required_targets=("heat_activity", "person"),
        default_dwell_seconds=1,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="hard_safety",
    ),
    ViolationType.SMOKE_ABNORMAL: ViolationDefinition(
        violation_type=ViolationType.SMOKE_ABNORMAL,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=True,
        required_zone_risk=None,
        required_targets=("smoke",),
        default_dwell_seconds=0,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="hard_safety",
    ),
    ViolationType.OPEN_FLAME: ViolationDefinition(
        violation_type=ViolationType.OPEN_FLAME,
        evidence_class=EvidenceClass.PRESENCE,
        is_hard_rule_eligible=True,
        required_zone_risk=None,
        required_targets=("open_flame",),
        default_dwell_seconds=0,
        default_cooldown_seconds=30,
        screening_prompt_id="screening_presence_v1",
        alert_policy_key="hard_safety",
    ),
}


def validate_violation_registry() -> None:
    if set(VIOLATION_REGISTRY) != set(ViolationType):
        missing = set(ViolationType) - set(VIOLATION_REGISTRY)
        extra = set(VIOLATION_REGISTRY) - set(ViolationType)
        raise ValueError(f"invalid violation registry coverage; missing={missing}, extra={extra}")
    for key, definition in VIOLATION_REGISTRY.items():
        if key != definition.violation_type:
            raise ValueError(f"registry key mismatch for {key}")


validate_violation_registry()
